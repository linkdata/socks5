package socks5

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"sync/atomic"
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
						errchan := make(chan error, 1)
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
	return c.fail(GeneralFailure, err)
}

const (
	maxUdpPacket = math.MaxUint16 - 28
)

type udpService struct {
	client     net.PacketConn
	clientaddr net.Addr
	target     net.Conn
	targetaddr Addr
	when       atomic.Int64
}

func (svc *udpService) serve() {
	defer svc.target.Close()
	var buf [maxUdpPacket]byte
	var err error
	for err == nil {
		var n int
		if n, err = svc.target.Read(buf[:]); err == nil {
			var b []byte
			if b, err = (&UDPPacket{Addr: svc.targetaddr, Body: buf[:n]}).AppendBinary(b); err == nil {
				var nn int
				if nn, err = svc.client.WriteTo(b, svc.clientaddr); err == nil {
					if err = MustEqual(nn, len(b), io.ErrShortWrite); err == nil {
						svc.when.Store(time.Now().UnixMilli())
					}
				}
			}
		}
	}
}

var UDPTimeout = time.Second * 5

func (c *client) serveUDP(ctx context.Context, errchan chan<- error, clientUDPConn net.PacketConn) {
	defer close(errchan)

	udpServicers := map[Addr]*udpService{}

	defer func() {
		for _, svc := range udpServicers {
			_ = svc.target.Close()
		}
	}()

	var clientAddr net.Addr
	var wantSource string
	var buf [maxUdpPacket]byte
	var err error
	for err == nil {
		var n int
		var addr net.Addr
		_ = clientUDPConn.SetReadDeadline(time.Now().Add(UDPTimeout))
		if n, addr, err = clientUDPConn.ReadFrom(buf[:]); err == nil {
			gotAddr := addr.String()
			if clientAddr == nil {
				clientAddr = addr
				wantSource = gotAddr
			}
			if wantSource == gotAddr {
				var pkt *UDPPacket
				if pkt, err = ParseUDPPacket(buf[:n]); err == nil {
					var svc *udpService
					if svc = udpServicers[pkt.Addr]; svc == nil {
						var targetConn net.Conn
						if targetConn, err = c.srv.DialContext(ctx, "udp", pkt.Addr.String()); err == nil {
							svc = &udpService{
								client:     clientUDPConn,
								clientaddr: clientAddr,
								target:     targetConn,
								targetaddr: pkt.Addr,
							}
							udpServicers[pkt.Addr] = svc
							go svc.serve()
						}
					}
					if svc != nil {
						var nn int
						if nn, err = svc.target.Write(pkt.Body); err == nil {
							if err = MustEqual(nn, len(pkt.Body), io.ErrShortWrite); err == nil {
								svc.when.Store(time.Now().UnixMilli())
							}
						}
					}
				}
			}
		} else if isTimeout(err) {
			err = nil
			timeout := time.Now().Add(-UDPTimeout).UnixMilli()
			for _, svc := range udpServicers {
				if when := svc.when.Load(); when < timeout {
					svc.target.Close()
					delete(udpServicers, svc.targetaddr)
				}
			}
		}
	}

	c.srv.logf("udp transfer: handle udp request fail: %v", err)
	errchan <- err
}

func isTimeout(err error) bool {
	terr, ok := errors.Unwrap(err).(interface{ Timeout() bool })
	return ok && terr.Timeout()
}
