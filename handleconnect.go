package socks5

import (
	"context"
	"io"
	"net"
	"time"
)

func (sess *session) handleCONNECT(ctx context.Context, addr string) (err error) {
	_ = sess.Debug && sess.LogDebug("CONNECT", "session", sess.conn.RemoteAddr(), "target", addr)

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var srv net.Conn
	if srv, err = sess.Server.DialContext(ctx, "tcp", addr); err == nil {
		defer srv.Close()
		localAddr := srv.LocalAddr().String()
		var serverAddr string
		var serverPort uint16
		if serverAddr, serverPort, err = SplitHostPort(localAddr); err == nil {
			res := &Response{
				Reply: Success,
				Addr:  AddrFromHostPort(serverAddr, serverPort),
			}
			var buf []byte
			if buf, err = res.MarshalBinary(); err == nil {
				if _, err = sess.conn.Write(buf); err == nil {
					errc := make(chan error, 2)
					go func() {
						_, err := io.Copy(sess.conn, srv)
						errc <- Note(err, "from backend to client")
					}()
					go func() {
						_, err := io.Copy(srv, sess.conn)
						errc <- Note(err, "from client to backend")
					}()
					return <-errc
				}
			}
		}
	}
	sess.maybeLogError(err, "CONNECT", "session", sess.conn.RemoteAddr(), "adress", addr)
	return sess.fail(GeneralFailure, err)
}
