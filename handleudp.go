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

const (
	maxUdpPacket = math.MaxUint16 - 28
)

var UDPTimeout = time.Second * 10

func (sess *session) handleUDP(ctx context.Context) (err error) {
	var host string
	if host, _, err = net.SplitHostPort(sess.conn.LocalAddr().String()); err == nil {
		var clientUDPConn net.PacketConn
		if clientUDPConn, err = net.ListenPacket("udp", net.JoinHostPort(host, "0")); err == nil {
			defer clientUDPConn.Close()
			var bindAddr string
			var bindPort uint16
			if bindAddr, bindPort, err = SplitHostPort(clientUDPConn.LocalAddr().String()); err == nil {
				res := &Response{
					Reply: Success,
					Addr:  AddrFromHostPort(bindAddr, bindPort),
				}
				var buf []byte
				if buf, err = res.MarshalBinary(); err == nil {
					if _, err = sess.conn.Write(buf); err == nil {
						err = sess.serveUDP(ctx, sess.conn, clientUDPConn)
					}
				}
			}
		}
	}
	return sess.fail(GeneralFailure, err)
}

type udpService struct {
	started    time.Time
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
						svc.when.Store(int64(time.Since(svc.started)))
					}
				}
			}
		}
	}
}

func (c *session) serveUDP(ctx context.Context, clientTCPConn net.Conn, clientUDPConn net.PacketConn) (err error) {
	go func() {
		_, _ = io.Copy(io.Discard, clientTCPConn)
		_ = clientUDPConn.Close()
	}()

	udpServicers := map[Addr]*udpService{}

	defer func() {
		for _, svc := range udpServicers {
			_ = svc.target.Close()
		}
	}()

	var clientAddr net.Addr
	var wantSource string
	var buf [maxUdpPacket]byte

	started := time.Now()
	err = clientUDPConn.SetReadDeadline(started.Add(UDPTimeout / 10))

	for err == nil {
		var n int
		var addr net.Addr
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
								started:    started,
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
								svc.when.Store(int64(time.Since(started)))
							}
						}
					}
				}
			}
		} else if isTimeout(err) {
			timeout := int64((time.Since(started) - UDPTimeout))
			for _, svc := range udpServicers {
				if when := svc.when.Load(); when < timeout {
					_ = svc.target.Close()
					delete(udpServicers, svc.targetaddr)
				}
			}
			err = clientUDPConn.SetReadDeadline(time.Now().Add(UDPTimeout / 10))
		}
	}

	return
}

func isTimeout(err error) bool {
	terr, ok := errors.Unwrap(err).(interface{ Timeout() bool })
	return ok && terr.Timeout()
}
