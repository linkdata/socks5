package client

import (
	"context"
	"net"
	"sync"

	"github.com/linkdata/socks5"
)

type boundTCP struct {
	cli      *Client
	ctx      context.Context
	addr     socks5.Addr   // address proxy server bound for listen
	ready    chan struct{} // semaphore to mark ready-for-new-accept
	mu       sync.Mutex    // protects following
	waitconn net.Conn      // waiting BIND
	currconn net.Conn      // current BIND
	err      error         // final error
}

var _ net.Listener = &boundTCP{}

func (cli *Client) bindTCP(ctx context.Context, address string) (bnd *boundTCP, err error) {
	var conn net.Conn
	var addr socks5.Addr
	if conn, addr, err = cli.do(ctx, socks5.BindCommand, address); err == nil {
		bnd = &boundTCP{
			cli:      cli,
			ctx:      ctx,
			ready:    make(chan struct{}, 1),
			addr:     addr,
			waitconn: conn,
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
			var addr socks5.Addr
			if addr, err = l.cli.readReply(currconn); err == nil {
				conn = &connect{Conn: currconn, remoteAddr: addr}
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
func (l *boundTCP) Addr() net.Addr {
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
