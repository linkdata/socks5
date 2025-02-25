package socks5

import (
	"context"
	"net"
)

type listener struct {
	ctx     context.Context
	d       *Dialer
	address string
}

// Accept waits for and returns the next connection to the listener.
func (l *listener) Accept() (conn net.Conn, err error) {
	if conn, err = l.d.do(l.ctx, BindCommand, l.address); err == nil {
		var addr Addr
		if addr, err = l.d.readReply(conn); err == nil {
			conn = &connect{Conn: conn, remoteAddr: addr}
		}
		err = Note(err, "listener.Accept")
	}
	return
}

// Close closes the listener.
func (l *listener) Close() error {
	return nil
}

// address returns the listener's network address.
func (l *listener) Addr() net.Addr {
	return nil
}
