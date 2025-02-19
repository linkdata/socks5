package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Conn is a SOCKS5 connection for client to reach
// server.
type Conn struct {
	// The struct is filled by each of the internal
	// methods in turn as the transaction progresses.

	logf       func(string, ...any)
	srv        *Server
	clientConn net.Conn
	request    *Request

	udpClientAddr  net.Addr
	udpTargetConns map[Addr]net.Conn
}

var ErrUnsupportedCommand = errors.New("unsupported command")

// Run starts the new connection.
func (c *Conn) Run() error {
	needAuth := c.srv.Username != "" || c.srv.Password != ""
	authMethod := NoAuthRequired
	if needAuth {
		authMethod = PasswordAuth
	}

	err := parseClientGreeting(c.clientConn, authMethod)
	if err != nil {
		c.clientConn.Write([]byte{Socks5Version, NoAcceptableAuth})
		return err
	}
	c.clientConn.Write([]byte{Socks5Version, authMethod})
	if !needAuth {
		return c.handleRequest()
	}

	user, pwd, err := parseClientAuth(c.clientConn)
	if err != nil || user != c.srv.Username || pwd != c.srv.Password {
		c.clientConn.Write([]byte{1, 1}) // auth error
		return err
	}
	c.clientConn.Write([]byte{1, 0}) // auth success

	return c.handleRequest()
}

func (c *Conn) handleRequest() (err error) {
	var req *Request
	replyCode := GeneralFailure
	if req, err = ReadRequest(c.clientConn); err == nil {
		c.request = req
		switch req.Cmd {
		case Connect:
			return c.handleTCP()
		case UdpAssociate:
			return c.handleUDP()
		default:
			replyCode = CommandNotSupported
			err = ErrUnsupportedCommand
		}
	}
	buf, _ := errorResponse(replyCode).MarshalBinary()
	c.clientConn.Write(buf)
	return
}

func (c *Conn) handleTCP() (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var srv net.Conn
	if srv, err = c.srv.dial(ctx, "tcp", c.request.Addr.HostPort()); err == nil {
		defer srv.Close()
		localAddr := srv.LocalAddr().String()
		var serverAddr string
		var serverPort uint16
		if serverAddr, serverPort, err = SplitHostPort(localAddr); err == nil {
			res := &Response{
				Reply: Success,
				Addr: Addr{
					Type: getAddrType(serverAddr),
					Addr: serverAddr,
					Port: serverPort,
				},
			}
			var buf []byte
			if buf, err = res.MarshalBinary(); err == nil {
				if _, err = c.clientConn.Write(buf); err == nil {
					errc := make(chan error, 2)
					go func() {
						_, err := io.Copy(c.clientConn, srv)
						if err != nil {
							err = fmt.Errorf("from backend to client: %w", err)
						}
						errc <- err
					}()
					go func() {
						_, err := io.Copy(srv, c.clientConn)
						if err != nil {
							err = fmt.Errorf("from client to backend: %w", err)
						}
						errc <- err
					}()
					return <-errc
				}
			}
		}
	}

	buf, _ := errorResponse(GeneralFailure).MarshalBinary()
	c.clientConn.Write(buf)
	return
}

func (c *Conn) handleUDP() (err error) {
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
					Addr: Addr{
						Type: getAddrType(bindAddr),
						Addr: bindAddr,
						Port: bindPort,
					},
				}
				var buf []byte
				if buf, err = res.MarshalBinary(); err == nil {
					if _, err = c.clientConn.Write(buf); err == nil {
						return c.transferUDP(c.clientConn, clientUDPConn)
					}
				}
			}
		}
	}
	buf, _ := errorResponse(GeneralFailure).MarshalBinary()
	c.clientConn.Write(buf)
	return
}

func (c *Conn) transferUDP(associatedTCP net.Conn, clientConn net.PacketConn) (err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// client -> target
	go func() {
		defer cancel()

		c.udpTargetConns = make(map[Addr]net.Conn)
		// close all target udp connections when the client connection is closed
		defer func() {
			for _, conn := range c.udpTargetConns {
				_ = conn.Close()
			}
		}()

		buf := make([]byte, bufferSize)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				err := c.handleUDPRequest(ctx, clientConn, buf)
				if err != nil {
					if isTimeout(err) {
						continue
					}
					if errors.Is(err, net.ErrClosed) {
						return
					}
					c.logf("udp transfer: handle udp request fail: %v", err)
				}
			}
		}
	}()

	// A UDP association terminates when the TCP connection that the UDP
	// ASSOCIATE request arrived on terminates. RFC1928
	_, err = io.Copy(io.Discard, associatedTCP)
	if err != nil {
		err = fmt.Errorf("udp associated tcp conn: %w", err)
	}
	return err
}

func (c *Conn) getOrDialTargetConn(ctx context.Context, clientConn net.PacketConn, targetAddr Addr) (conn net.Conn, err error) {
	var exist bool
	if conn, exist = c.udpTargetConns[targetAddr]; !exist {
		if conn, err = c.srv.dial(ctx, "udp", targetAddr.HostPort()); err == nil {
			c.udpTargetConns[targetAddr] = conn
			go func() {
				buf := make([]byte, bufferSize)
				for {
					select {
					case <-ctx.Done():
						return
					default:
						err := c.handleUDPResponse(clientConn, targetAddr, conn, buf)
						if err != nil {
							if isTimeout(err) {
								continue
							}
							if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
								return
							}
							c.logf("udp transfer: handle udp response fail: %v", err)
						}
					}
				}
			}()
		}
	}
	return
}

func (c *Conn) handleUDPRequest(ctx context.Context, clientConn net.PacketConn, buf []byte) (err error) {
	_ = clientConn.SetReadDeadline(time.Now().Add(readTimeout))
	var n int
	var addr net.Addr
	if n, addr, err = clientConn.ReadFrom(buf); err == nil {
		c.udpClientAddr = addr
		var req *UdpRequest
		var data []byte
		if req, data, err = ParseUDPRequest(buf[:n]); err == nil {
			var targetConn net.Conn
			if targetConn, err = c.getOrDialTargetConn(ctx, clientConn, req.Addr); err == nil {
				var nn int
				if nn, err = targetConn.Write(data); err == nil {
					err = MustEqual(nn, len(data), io.ErrShortWrite)
				}
			}
		}
	}
	return
}

func (c *Conn) handleUDPResponse(clientConn net.PacketConn, targetAddr Addr, targetConn net.Conn, buf []byte) (err error) {
	_ = targetConn.SetReadDeadline(time.Now().Add(readTimeout))
	var n int
	if n, err = targetConn.Read(buf); err == nil {
		hdr := UdpRequest{Addr: targetAddr}
		var pkt []byte
		if pkt, err = hdr.AppendBinary(pkt); err == nil {
			pkt = append(pkt, buf[:n]...)
			var nn int
			if nn, err = clientConn.WriteTo(pkt, c.udpClientAddr); err == nil {
				err = MustEqual(nn, len(pkt), io.ErrShortWrite)
			}
		}
	}
	return
}
