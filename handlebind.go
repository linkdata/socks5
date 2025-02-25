package socks5

import (
	"context"
	"io"
	"net"
)

func sendReply(w io.Writer, resp ReplyCode, addr Addr) (err error) {
	var b []byte
	b = append(b, Socks5Version, byte(resp), 0)
	if b, err = addr.AppendBinary(b); err == nil {
		_, err = w.Write(b)
	}
	return
}

func (sess *session) handleBIND(ctx context.Context, bindaddr string) (err error) {
	var lc net.ListenConfig
	var listener net.Listener
	if listener, err = lc.Listen(ctx, "tcp", bindaddr); err == nil {
		var addr Addr
		if addr, err = AddrFromString(listener.Addr().String()); err == nil {
			addr.ReplaceAny(sess.conn.LocalAddr().String())
			if err = sendReply(sess.conn, Success, addr); err == nil {
				_ = sess.Debug && sess.LogDebug("BIND", "session", sess.conn.RemoteAddr(), "listen", addr)
				var conn net.Conn
				if conn, err = listener.Accept(); err == nil {
					_ = listener.Close()
					var remoteAddr Addr
					if remoteAddr, err = AddrFromString(conn.RemoteAddr().String()); err == nil {
						_ = sess.Debug && sess.LogDebug("BIND", "session", sess.conn.RemoteAddr(), "remote", remoteAddr)
						if err = sendReply(sess.conn, Success, remoteAddr); err == nil {
							defer conn.Close()
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
							return
						}
					}
				}
			}
		}
		_ = listener.Close()
	}
	_ = sendReply(sess.conn, GeneralFailure, ZeroAddr)
	return
}
