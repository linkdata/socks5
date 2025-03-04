package server

import (
	"context"
	"io"
	"net"

	"github.com/linkdata/socks5"
)

func sendReply(w io.Writer, resp socks5.ReplyCode, addr socks5.Addr) (err error) {
	var b []byte
	b = append(b, socks5.Socks5Version, byte(resp), 0)
	if b, err = addr.AppendBinary(b); err == nil {
		_, err = w.Write(b)
	}
	return
}

func (sess *session) handleBIND(ctx context.Context, bindaddr string) (err error) {
	var listener net.Listener
	_ = sess.Debug && sess.LogDebug("BIND", "session", sess.conn.RemoteAddr(), "bindaddr", bindaddr)
	if listener, err = sess.getListener(ctx, bindaddr); err == nil {
		defer listener.Close()
		var addr socks5.Addr
		if addr, err = socks5.AddrFromString(listener.Addr().String()); err == nil {
			if err = sendReply(sess.conn, socks5.Success, addr); err == nil {
				_ = sess.Debug && sess.LogDebug("BIND", "session", sess.conn.RemoteAddr(), "listen", addr)
				var conn net.Conn
				if conn, err = listener.Accept(); err == nil {
					defer conn.Close()
					var remoteAddr socks5.Addr
					if remoteAddr, err = socks5.AddrFromString(conn.RemoteAddr().String()); err == nil {
						_ = sess.Debug && sess.LogDebug("BIND", "session", sess.conn.RemoteAddr(), "remote-bound", remoteAddr)
						if err = sendReply(sess.conn, socks5.Success, remoteAddr); err == nil {
							_ = sess.Debug && sess.LogDebug("BIND", "session", sess.conn.RemoteAddr(), "remote-start", remoteAddr)
							ctx, cancel := context.WithCancel(ctx)
							go func() {
								_, _ = io.Copy(sess.conn, conn)
								cancel()
							}()
							go func() {
								_, _ = io.Copy(conn, sess.conn)
								cancel()
							}()
							<-ctx.Done()
							_ = sess.Debug && sess.LogDebug("BIND", "session", sess.conn.RemoteAddr(), "remote-stop", remoteAddr)
							return
						}
					}
				}
			}
		}
	}
	sess.maybeLogError(err, "BIND", "session", sess.conn.RemoteAddr(), "adress", bindaddr)
	_ = sendReply(sess.conn, socks5.GeneralFailure, socks5.ZeroAddr)
	return
}
