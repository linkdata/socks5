package client

import (
	"context"
	"net"
	"sync"

	"github.com/linkdata/socks5"
)

type boundTCP struct {
	cli   *Client
	ctx   context.Context
	addr  socks5.Addr   // address proxy server bound for listen
	ready chan struct{} // semaphore to mark ready-for-new-accept
	mu    sync.Mutex    // protects following
	conn  net.Conn      // waiting BIND
	err   error         // final error
}

var _ net.Listener = &boundTCP{}

func (cli *Client) bindTCP(ctx context.Context, address string) (bnd *boundTCP, err error) {
	var conn net.Conn
	var addr socks5.Addr
	if conn, addr, err = cli.do(ctx, socks5.BindCommand, address); err == nil {
		bnd = &boundTCP{
			cli:   cli,
			ctx:   ctx,
			ready: make(chan struct{}, 1),
			addr:  addr,
			conn:  conn,
		}
		bnd.ready <- struct{}{}
	}
	return
}

func (l *boundTCP) startAccept() (conn net.Conn, addr socks5.Addr, err error) {
	conn, addr, err = l.cli.do(l.ctx, socks5.BindCommand, l.addr.String())
	return
}

// Accept waits for and returns the next connection to the listener.
func (l *boundTCP) Accept() (conn net.Conn, err error) {
	var currconn net.Conn
	l.mu.Lock()
	err = l.err
	l.mu.Unlock()
	if err == nil {
		if _, ok := <-l.ready; ok {
			l.mu.Lock()
			if err = l.err; err == nil {
				currconn = l.conn
			}
			l.mu.Unlock()
			if currconn != nil {
				var addr socks5.Addr
				if addr, err = l.cli.readReply(currconn); err == nil {
					conn = &connect{Conn: currconn, remoteAddr: addr}
				}
				l.mu.Lock()
				if l.err == nil {
					l.conn, _, l.err = l.startAccept()
					l.ready <- struct{}{}
				}
				l.mu.Unlock()
			}
		}
	}
	err = socks5.Note(err, "binding.Accept")
	return
}

// Close closes the listener.
func (l *boundTCP) Close() (err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err == nil {
		l.err = net.ErrClosed
	}
	if l.conn != nil {
		err = l.conn.Close()
		l.conn = nil
	}
	if l.ready != nil {
		close(l.ready)
		l.ready = nil
	}
	return
}

// Addr returns the listener's address and port on the proxy server.
// If listening on the ANY address (0.0.0.0 or ::), it will return the proxy servers address instead of that.
func (l *boundTCP) Addr() net.Addr {
	l.mu.Lock()
	addr := l.addr
	conn := l.conn
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
