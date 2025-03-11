package server

import (
	"net"
	"sync/atomic"
	"time"
)

type listener struct {
	srv *Server
	key string
	net.Listener
	refs atomic.Int32
	died atomic.Int64
}

func (l *listener) Close() (err error) {
	if refs := l.refs.Add(-1); refs < 1 {
		died := int64(time.Since(l.srv.started))
		l.died.Store(died)
		_ = l.srv.Debug && l.srv.LogDebug("listener deref", "key", l.key, "refs", refs, "died", died)
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
