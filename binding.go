package socks5

import (
	"context"
	"net"
	"sync"
)

type binding struct {
	cli      *Client
	ctx      context.Context
	addr     Addr          // address proxy server bound for listen
	ready    chan struct{} // semaphore to mark ready-for-new-accept
	mu       sync.Mutex    // protects following
	waitconn net.Conn      // waiting BIND
	currconn net.Conn      // current BIND
	err      error         // final error
}

func newBinding(ctx context.Context, cli *Client, network, address string) (bnd *binding, err error) {
	err = ErrUnsupportedNetwork
	switch network {
	case "tcp", "tcp4", "tcp6":
		var conn net.Conn
		var addr Addr
		if conn, addr, err = cli.do(ctx, BindCommand, address); err == nil {
			bnd = &binding{
				cli:      cli,
				ctx:      ctx,
				ready:    make(chan struct{}, 1),
				addr:     addr,
				waitconn: conn,
			}
			bnd.ready <- struct{}{}
		}
	}
	return
}

func (l *binding) startAccept() (conn net.Conn, addr Addr, err error) {
	conn, addr, err = l.cli.do(l.ctx, BindCommand, l.addr.String())
	return
}

// Accept waits for and returns the next connection to the listener.
func (l *binding) Accept() (conn net.Conn, err error) {
	var currconn net.Conn
	l.mu.Lock()
	err = l.err
	l.mu.Unlock()
	if err == nil {
		<-l.ready
		l.mu.Lock()
		if err = l.err; err == nil {
			currconn = l.waitconn
			l.currconn = currconn
			l.waitconn, _, l.err = l.startAccept()
		}
		l.mu.Unlock()
		if currconn != nil {
			defer func() {
				l.ready <- struct{}{}
			}()
			var addr Addr
			if addr, err = l.cli.readReply(currconn); err == nil {
				conn = &connect{Conn: currconn, remoteAddr: addr}
			}
		}
	}
	err = Note(err, "binding.Accept")
	return
}

// Close closes the listener.
func (l *binding) Close() (err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err == nil {
		l.err = net.ErrClosed
	}
	if l.waitconn != nil {
		err = l.waitconn.Close()
		l.waitconn = nil
	}
	if l.currconn != nil {
		err = l.currconn.Close()
		l.currconn = nil
		<-l.ready
		close(l.ready)
	}
	return
}

// Addr returns the listener's address and port on the proxy server.
// If listening on the ANY address (0.0.0.0 or ::), it will return the proxy servers address instead of that.
func (l *binding) Addr() net.Addr {
	l.mu.Lock()
	addr := l.addr
	conn := l.waitconn
	l.mu.Unlock()
	if conn != nil {
		addr.ReplaceAny(conn.RemoteAddr().String())
	}
	return addr
}

type connect struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *connect) RemoteAddr() net.Addr {
	return c.remoteAddr
}
