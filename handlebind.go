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

func (c *session) handleBind(ctx context.Context, addr string) (err error) {
	var lc net.ListenConfig
	var listener net.Listener
	if listener, err = lc.Listen(ctx, "tcp", addr); err == nil {
		var addr Addr
		if addr, err = AddrFromString(listener.Addr().String()); err == nil {
			if err = sendReply(c.clientConn, Success, addr); err == nil {
				var conn net.Conn
				if conn, err = listener.Accept(); err == nil {
					listener.Close()
					var remoteAddr Addr
					if remoteAddr, err = AddrFromString(conn.RemoteAddr().String()); err == nil {
						if err = sendReply(c.clientConn, Success, remoteAddr); err == nil {
							defer conn.Close()
							ctx, cancel := context.WithCancel(ctx)
							go func() {
								_, _ = io.Copy(c.clientConn, conn)
								cancel()
							}()
							go func() {
								_, _ = io.Copy(conn, c.clientConn)
								cancel()
							}()
							<-ctx.Done()
							return
						}
					}
				}
			}
		}
		listener.Close()
	}
	_ = sendReply(c.clientConn, GeneralFailure, ZeroAddr)
	return
}
