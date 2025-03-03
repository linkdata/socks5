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

func (sess *session) handleASSOCIATE(ctx context.Context, clientAddr Addr) (err error) {
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
						_ = sess.Debug && sess.LogDebug("ASSOCIATE", "session", sess.conn.RemoteAddr(), "address", res.Addr)
						err = sess.serveUDP(ctx, sess.conn, clientAddr, res.Addr, clientUDPConn)
					}
				}
			}
		}
	}
	sess.maybeLogError(err, "ASSOCIATE", "session", sess.conn.RemoteAddr())
	return sess.fail(GeneralFailure, err)
}

func (c *session) serveUDP(ctx context.Context, clientTCPConn net.Conn, clientAddr, srvAddr Addr, clientUDPConn net.PacketConn) (err error) {
	var tcpClosed atomic.Bool
	go func() {
		_, _ = io.Copy(io.Discard, clientTCPConn)
		tcpClosed.Store(true)
		_ = clientUDPConn.Close()
	}()

	udpServicers := map[Addr]*udpService{}

	defer func() {
		for _, svc := range udpServicers {
			_ = svc.target.Close()
		}
	}()

	var clientNetAddr net.Addr
	var clientAddress string
	var buf [maxUdpPacket]byte

	if !clientAddr.IsZero() {
		clientAddr.ReplaceAny(clientTCPConn.RemoteAddr().String())
		if clientAddr.Port == 0 {
			clientAddr.Port = srvAddr.Port
		}
		clientNetAddr = clientAddr
	}

	started := time.Now()
	err = clientUDPConn.SetReadDeadline(started.Add(UDPTimeout / 10))

	for err == nil {
		var n int
		var addr net.Addr
		if n, addr, err = clientUDPConn.ReadFrom(buf[:]); err == nil {
			gotAddr := addr.String()
			if clientNetAddr == nil {
				clientNetAddr = addr
				clientAddress = gotAddr
			}
			if clientAddress == gotAddr {
				var pkt *UDPPacket
				if pkt, err = ParseUDPPacket(buf[:n]); err == nil {
					var svc *udpService
					if svc = udpServicers[pkt.Addr]; svc == nil {
						var targetConn net.Conn
						if targetConn, err = c.Server.DialContext(ctx, "udp", pkt.Addr.String()); err == nil {
							svc = &udpService{
								srv:        c.Server,
								started:    started,
								client:     clientUDPConn,
								clientaddr: clientNetAddr,
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

	if tcpClosed.Load() {
		err = nil
	}

	return
}

func isTimeout(err error) bool {
	terr, ok := errors.Unwrap(err).(interface{ Timeout() bool })
	return ok && terr.Timeout()
}

type udpService struct {
	srv        *Server
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
	pktconn := svc.target.(net.PacketConn)
	for err == nil {
		var n int
		var srcnetaddr net.Addr
		if n, srcnetaddr, err = pktconn.ReadFrom(buf[:]); err == nil {
			var srcaddr Addr
			if srcaddr, err = AddrFromString(srcnetaddr.String()); err == nil {
				var b []byte
				if b, err = (&UDPPacket{Addr: srcaddr, Body: buf[:n]}).MarshalBinary(); err == nil {
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
	svc.srv.LogError("udpService.serve()", "error", err, "client", svc.client.LocalAddr().String(), "target", svc.target.RemoteAddr().String(), "targetaddr", svc.targetaddr.String())
}
