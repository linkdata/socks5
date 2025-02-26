package socks5

import (
	"context"
	"net"
)

type listener struct {
	ctx     context.Context
	d       *Client
	address string
}

func newListener(ctx context.Context, d *Client, network, address string) (l *listener, err error) {
	err = ErrUnsupportedNetwork
	switch network {
	case "tcp", "tcp4", "tcp6":
		l = &listener{ctx: ctx, d: d, address: address}
		err = nil
	}
	return
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

type connect struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *connect) RemoteAddr() net.Addr {
	return c.remoteAddr
}
