package server

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/linkdata/socks5"
)

// Server is a SOCKS5 proxy server.
type Server struct {
	Started time.Time // time when Server.Serve() was called

	// List of authentication providers. If nil, uses NoAuthAuthenticator.
	// Order matters; they are tried in the given order.
	Authenticators []Authenticator

	// DialerSelector is called to get the ContextDialer to use for an outgoing connection.
	// If nil, socks5.DefaultDialer will be used, which if not changed is a net.Dialer.
	DialerSelector

	Logger socks5.Logger // If not nil, use this Logger (compatible with log/slog)
	Debug  bool          // If true, output debug logging using Logger.Info

	closed    atomic.Bool
	mu        sync.Mutex // protects following
	listeners map[string]*listener
}

func listenKey(client net.Conn, address string) (key string) {
	if host, port, err := net.SplitHostPort(address); err == nil {
		if port != "0" {
			if host == "0.0.0.0" || host == "::" {
				host = ""
			}
			if clienthost, _, err := net.SplitHostPort(client.RemoteAddr().String()); err == nil {
				key = net.JoinHostPort(host, port) + "@" + clienthost
			}
		}
	}
	return
}

func (s *Server) getListener(ctx context.Context, client net.Conn, bindaddress string) (nl net.Listener, err error) {
	err = net.ErrClosed
	if !s.closed.Load() {
		err = nil
		key := listenKey(client, bindaddress)
		var lc net.ListenConfig
		var newlistener net.Listener
		if key == "" {
			if newlistener, err = lc.Listen(ctx, "tcp", bindaddress); err == nil {
				bindaddress = newlistener.Addr().String()
				key = listenKey(client, bindaddress)
			}
		}
		if err == nil {
			s.mu.Lock()
			defer s.mu.Unlock()
			l := s.listeners[key]
			if l == nil {
				if newlistener == nil {
					newlistener, err = lc.Listen(ctx, "tcp", bindaddress)
				}
				if err == nil {
					l = &listener{
						srv:      s,
						key:      key,
						Listener: newlistener,
					}
					s.listeners[key] = l
					_ = s.Debug && s.LogDebug("listener open", "key", key)
				}
			}
			if l != nil {
				refs := l.refs.Add(1)
				nl = &listenerproxy{listener: l}
				_ = s.Debug && s.LogDebug("listener addref", "key", key, "refs", refs)
			}
		}
	}
	return
}

func (s *Server) LogDebug(msg string, keyvaluepairs ...any) bool {
	if s.Debug && s.Logger != nil {
		s.Logger.Info(socks5.LogPrefix+msg, keyvaluepairs...)
	}
	return true
}

func (s *Server) LogInfo(msg string, keyvaluepairs ...any) {
	if s.Logger != nil {
		s.Logger.Info(socks5.LogPrefix+msg, keyvaluepairs...)
	}
}

func (s *Server) LogError(msg string, keyvaluepairs ...any) {
	if s.Logger != nil {
		s.Logger.Error(socks5.LogPrefix+msg, keyvaluepairs...)
	}
}

func (s *Server) maybeLogError(err error, msg string, keyvaluepairs ...any) {
	if err != nil && s.Logger != nil {
		keyvaluepairs = append(keyvaluepairs, "error", err)
		s.Logger.Error(socks5.LogPrefix+msg, keyvaluepairs...)
	}
}

func (s *Server) close() {
	if !s.closed.Swap(true) {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, l := range s.listeners {
			_ = s.Debug && s.LogDebug("Server.close(): listener stop", "address", l.key)
			l.refs.Store(0)
			_ = l.Listener.Close()
		}
		clear(s.listeners)
	}
}

// Serve accepts and handles incoming connections on the given listener.
func (s *Server) Serve(ctx context.Context, l net.Listener) (err error) {
	defer l.Close()
	defer s.close()
	s.Started = time.Now()
	errchan := make(chan error, 1)
	s.LogInfo("listening", "addr", l.Addr())
	s.listeners = make(map[string]*listener)
	go s.listenerMaintenance(ctx)
	go s.listen(ctx, errchan, l)
	select {
	case <-ctx.Done():
	case err = <-errchan:
	}
	return
}

func (s *Server) listenerCleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	deadline := int64(time.Since(s.Started) - socks5.ListenerTimeout)
	for k, l := range s.listeners {
		if refs := l.refs.Load(); refs < 1 {
			if died := l.died.Load(); died < deadline {
				delete(s.listeners, k)
				_ = l.Listener.Close()
				_ = s.Debug && s.LogDebug("listener closed", "key", k, "refs", refs, "died", died)
			}
		}
	}
}

func (s *Server) listenerMaintenance(ctx context.Context) {
	tmr := time.NewTicker(socks5.ListenerTimeout)
	defer tmr.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tmr.C:
			s.listenerCleanup()
		}
	}
}

func (s *Server) listen(ctx context.Context, errchan chan<- error, l net.Listener) {
	defer close(errchan)
	var err error
	for err == nil {
		var clientConn net.Conn
		if clientConn, err = l.Accept(); err == nil {
			go s.startConn(ctx, clientConn)
		}
	}
	errchan <- err
}

func (s *Server) startConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()
	_ = s.Debug && s.LogDebug("session start", "session", clientConn.RemoteAddr())
	conn := &session{conn: clientConn, Server: s}
	err := conn.serve(ctx)
	_ = s.Debug && s.LogDebug("session stop", "session", clientConn.RemoteAddr(), "err", err)
}

func readClientGreeting(r io.Reader) (authMethods []socks5.AuthMethod, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(r, hdr[:]); err == nil {
		if err = socks5.MustEqual(hdr[0], socks5.Socks5Version, socks5.ErrVersion); err == nil {
			count := int(hdr[1])
			methods := make([]byte, count)
			if _, err = io.ReadFull(r, methods); err == nil {
				for _, m := range methods {
					authMethods = append(authMethods, socks5.AuthMethod(m))
				}
			}
		}
	}
	return
}
