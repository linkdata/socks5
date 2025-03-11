package server

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"sync/atomic"
	"time"

	"github.com/linkdata/socks5"
)

const (
	maxUdpPacket = math.MaxUint16 - 28
)

func (sess *session) handleASSOCIATE(ctx context.Context) (err error) {
	var host string
	if host, _, err = net.SplitHostPort(sess.conn.LocalAddr().String()); err == nil {
		var clientUDPConn net.PacketConn
		if clientUDPConn, err = net.ListenPacket("udp", net.JoinHostPort(host, "0")); err == nil {
			defer clientUDPConn.Close()
			var bindAddr string
			var bindPort uint16
			if bindAddr, bindPort, err = socks5.SplitHostPort(clientUDPConn.LocalAddr().String()); err == nil {
				res := &Response{
					Reply: socks5.Success,
					Addr:  socks5.AddrFromHostPort(bindAddr, bindPort),
				}
				var buf []byte
				if buf, err = res.MarshalBinary(); err == nil {
					if _, err = sess.conn.Write(buf); err == nil {
						_ = sess.Debug && sess.LogDebug("ASSOCIATE", "session", sess.conn.RemoteAddr(), "address", res.Addr)
						err = sess.serveUDP(ctx, sess.conn, clientUDPConn)
					}
				}
			}
		}
	}
	sess.maybeLogError(err, "ASSOCIATE", "session", sess.conn.RemoteAddr())
	return sess.fail(socks5.GeneralFailure, err)
}

func (sess *session) serveUDP(ctx context.Context, clientTCPConn net.Conn, clientUDPConn net.PacketConn) (err error) {
	var tcpClosed atomic.Bool
	go func() {
		_, _ = io.Copy(io.Discard, clientTCPConn)
		tcpClosed.Store(true)
		_ = clientUDPConn.Close()
	}()

	udpServicers := map[socks5.Addr]*udpService{}

	defer func() {
		for _, svc := range udpServicers {
			_ = svc.target.Close()
		}
	}()

	var clientNetAddr net.Addr
	var clientAddress string
	var buf [maxUdpPacket]byte

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
				var pkt *socks5.UDPPacket
				if pkt, err = socks5.ParseUDPPacket(buf[:n]); err == nil {
					var svc *udpService
					if svc = udpServicers[pkt.Addr]; svc == nil {
						var targetConn net.Conn
						if targetConn, err = sess.DialContext(ctx, "udp", pkt.Addr.String()); err == nil {
							svc = &udpService{
								srv:        sess.Server,
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
							if err = socks5.MustEqual(nn, len(pkt.Body), io.ErrShortWrite); err == nil {
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
	targetaddr socks5.Addr
	when       atomic.Int64
}

func (svc *udpService) serve() {
	defer svc.target.Close()
	err := socks5.ErrUnsupportedNetwork
	pktconn, ok := svc.target.(net.PacketConn)
	if ok {
		var buf [maxUdpPacket]byte
		err = nil
		for err == nil {
			var n int
			var srcnetaddr net.Addr
			if n, srcnetaddr, err = pktconn.ReadFrom(buf[:]); err == nil {
				var srcaddr socks5.Addr
				if srcaddr, err = socks5.AddrFromString(srcnetaddr.String()); err == nil {
					var b []byte
					if b, err = (&socks5.UDPPacket{Addr: srcaddr, Body: buf[:n]}).MarshalBinary(); err == nil {
						var nn int
						if nn, err = svc.client.WriteTo(b, svc.clientaddr); err == nil {
							if err = socks5.MustEqual(nn, len(b), io.ErrShortWrite); err == nil {
								svc.when.Store(int64(time.Since(svc.started)))
							}
						}
					}
				}
			}
		}
	}
	svc.srv.LogError("udpService.serve()", "error", err, "client", svc.client.LocalAddr().String(), "target", svc.target.RemoteAddr().String(), "targetaddr", svc.targetaddr.String())
}
