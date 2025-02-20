package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

func (c *client) handleTCP(ctx context.Context, addr string) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var srv net.Conn
	if srv, err = c.srv.DialContext(ctx, "tcp", addr); err == nil {
		defer srv.Close()
		localAddr := srv.LocalAddr().String()
		var serverAddr string
		var serverPort uint16
		if serverAddr, serverPort, err = SplitHostPort(localAddr); err == nil {
			res := &Response{
				Reply: Success,
				Addr:  MakeAddr(serverAddr, serverPort),
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
	return c.fail(GeneralFailure, err)
}
