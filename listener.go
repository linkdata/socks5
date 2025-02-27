package socks5

import (
	"net"
	"sync/atomic"
)

type listener struct {
	srv *Server
	key string
	net.Listener
	refs atomic.Int32
}

func (l *listener) Close() (err error) {
	if l.refs.Add(-1) == 0 {
		l.srv.mu.Lock()
		if l.srv.listeners != nil {
			_ = l.srv.Debug && l.srv.LogDebug("listener.Close(): listener stop", "address", l.key)
			err = l.Listener.Close()
			delete(l.srv.listeners, l.key)
		}
		l.srv.mu.Unlock()
	}
	return
}

type listenerproxy struct {
	*listener
	closed atomic.Bool
}

func (l *listenerproxy) Close() (err error) {
	if !l.closed.Swap(true) {
		err = l.listener.Close()
	}
	return
}
