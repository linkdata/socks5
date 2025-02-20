package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

func awaitTCPClose(conn net.Conn, ch chan struct{}) {
	defer close(ch)
	_, _ = io.Copy(io.Discard, conn)
}

func (c *client) handleUDP(ctx context.Context) (err error) {
	var host string
	if host, _, err = net.SplitHostPort(c.clientConn.LocalAddr().String()); err == nil {
		var clientUDPConn net.PacketConn
		if clientUDPConn, err = net.ListenPacket("udp", net.JoinHostPort(host, "0")); err == nil {
			defer clientUDPConn.Close()
			var bindAddr string
			var bindPort uint16
			if bindAddr, bindPort, err = SplitHostPort(clientUDPConn.LocalAddr().String()); err == nil {
				res := &Response{
					Reply: Success,
					Addr:  MakeAddr(bindAddr, bindPort),
				}
				var buf []byte
				if buf, err = res.MarshalBinary(); err == nil {
					if _, err = c.clientConn.Write(buf); err == nil {
						errchan := make(chan error)
						closechan := make(chan struct{})
						go awaitTCPClose(c.clientConn, closechan)
						go c.serveUDP(ctx, errchan, clientUDPConn)
						select {
						case <-closechan:
						case err = <-errchan:
						}
						return
					}
				}
			}
		}
	}
	buf, _ := errorResponse(GeneralFailure).MarshalBinary()
	c.clientConn.Write(buf)
	return
}

func ignoreTimeout(err error) error {
	if isTimeout(err) {
		err = nil
	}
	return err
}

func (c *client) serveUDP(ctx context.Context, errchan chan<- error, clientUDPConn net.PacketConn) {
	defer close(errchan)

	udpTargetConns := map[Addr]net.Conn{}

	defer func() {
		for _, conn := range udpTargetConns {
			_ = conn.Close()
		}
	}()

	buf := make([]byte, bufferSize)
	var err error
	for err == nil {
		select {
		case <-ctx.Done():
			return
		default:
			var req *UdpRequest
			if req, err = c.readUDPRequest(clientUDPConn, buf); req != nil {
				var targetConn net.Conn
				if targetConn = udpTargetConns[req.Addr]; targetConn == nil {
					if targetConn, err = c.srv.DialContext(ctx, "udp", req.Addr.String()); err == nil {
						udpTargetConns[req.Addr] = targetConn
						go c.serveUDPResponses(clientUDPConn, targetConn, req.Addr)
					}
				}
				if targetConn != nil {
					var nn int
					if nn, err = targetConn.Write(req.Body); err == nil {
						err = MustEqual(nn, len(req.Body), io.ErrShortWrite)
					}
				}
			} else {
				if errors.Is(err, net.ErrClosed) {
					return
				}
			}
		}
	}
	c.srv.logf("udp transfer: handle udp request fail: %v", err)
	errchan <- err
}

func (c *client) readUDPRequest(clientUDPConn net.PacketConn, buf []byte) (req *UdpRequest, err error) {
	_ = clientUDPConn.SetReadDeadline(time.Now().Add(readTimeout))
	var n int
	var addr net.Addr
	if n, addr, err = clientUDPConn.ReadFrom(buf); err == nil {
		c.udpClientAddr = addr
		req, err = ParseUDPRequest(buf[:n])
	}
	err = ignoreTimeout(err)
	return
}

func (c *client) serveUDPResponses(clientUDPConn net.PacketConn, targetConn net.Conn, targetAddr Addr) {
	buf := make([]byte, bufferSize)
	var err error
	for err == nil {
		var req *UdpRequest
		if req, err = c.readUDPResponse(targetAddr, targetConn, buf); req != nil {
			var pkt []byte
			if pkt, err = req.AppendBinary(pkt); err == nil {
				var nn int
				if nn, err = clientUDPConn.WriteTo(pkt, c.udpClientAddr); err == nil {
					err = MustEqual(nn, len(pkt), io.ErrShortWrite)
				}
			}
		} else {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
		}
	}
}

func (c *client) readUDPResponse(targetAddr Addr, targetConn net.Conn, buf []byte) (req *UdpRequest, err error) {
	_ = targetConn.SetReadDeadline(time.Now().Add(readTimeout))
	var n int
	if n, err = targetConn.Read(buf); err == nil {
		req = &UdpRequest{Addr: targetAddr}
		req.Body = append(req.Body, buf[:n]...)
	}
	err = ignoreTimeout(err)
	return
}
