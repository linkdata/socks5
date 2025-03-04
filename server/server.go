package server

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/linkdata/socks5"
)

// Server is a SOCKS5 proxy server.
type Server struct {
	// Dialer optionally specifies the ContextDialer to use for outgoing connections.
	// If nil, DefaultDialer will be used, which if not changed is a net.Dialer.
	Dialer socks5.ContextDialer

	// Username and Password, if set, are the credential clients must provide.
	Username string
	Password string

	// If not nil, use this Logger (compatible with log/slog)
	Logger socks5.Logger
	Debug  bool // if true, output debug logging using Logger.Info

	closed    atomic.Bool
	mu        sync.Mutex // protects following
	listeners map[string]*listener
}

var DefaultDialer socks5.ContextDialer = &net.Dialer{}
var LogPrefix = "socks5: "

func (s *Server) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := s.Dialer
	if dialer == nil {
		dialer = DefaultDialer
	}
	return dialer.DialContext(ctx, network, addr)
}

func listenKey(address string) (key string) {
	if host, port, err := net.SplitHostPort(address); err == nil {
		if port != "0" {
			if host == "0.0.0.0" || host == "::" {
				host = ""
			}
			key = net.JoinHostPort(host, port)
		}
	}
	return
}

func (s *Server) getListener(ctx context.Context, address string) (nl net.Listener, err error) {
	err = net.ErrClosed
	if !s.closed.Load() {
		err = nil
		key := listenKey(address)
		var lc net.ListenConfig
		var newlistener net.Listener
		if key == "" {
			if newlistener, err = lc.Listen(ctx, "tcp", address); err == nil {
				address = newlistener.Addr().String()
				key = listenKey(address)
			}
		}
		if err == nil {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.listeners == nil {
				s.listeners = make(map[string]*listener)
			}
			l := s.listeners[key]
			if l == nil {
				if newlistener == nil {
					newlistener, err = lc.Listen(ctx, "tcp", address)
				}
				if err == nil {
					l = &listener{
						srv:      s,
						key:      key,
						Listener: newlistener,
					}
					s.listeners[key] = l
					_ = s.Debug && s.LogDebug("server listener start", "adress", key)
				}
			}
			if l != nil {
				l.refs.Add(1)
				nl = &listenerproxy{listener: l}
			}
		}
	}
	return
}

func (s *Server) LogDebug(msg string, keyvaluepairs ...any) bool {
	if s.Debug && s.Logger != nil {
		s.Logger.Info(LogPrefix+msg, keyvaluepairs...)
	}
	return true
}

func (s *Server) LogInfo(msg string, keyvaluepairs ...any) {
	if s.Logger != nil {
		s.Logger.Info(LogPrefix+msg, keyvaluepairs...)
	}
}

func (s *Server) LogError(msg string, keyvaluepairs ...any) {
	if s.Logger != nil {
		s.Logger.Error(LogPrefix+msg, keyvaluepairs...)
	}
}

func (s *Server) maybeLogError(err error, msg string, keyvaluepairs ...any) {
	if err != nil && s.Logger != nil {
		keyvaluepairs = append(keyvaluepairs, "error", err)
		s.Logger.Error(LogPrefix+msg, keyvaluepairs...)
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
	errchan := make(chan error, 1)
	s.LogInfo("listening", "addr", l.Addr())
	go s.listen(ctx, errchan, l)
	select {
	case <-ctx.Done():
	case err = <-errchan:
	}
	return
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

func parseClientAuth(r io.Reader) (usr, pwd string, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(r, hdr[:]); err == nil {
		if err = socks5.MustEqual(hdr[0], socks5.PasswordAuthVersion, socks5.ErrBadSOCKSAuthVersion); err == nil {
			usrLen := int(hdr[1])
			usrBytes := make([]byte, usrLen)
			if _, err = io.ReadFull(r, usrBytes); err == nil {
				var hdrPwd [1]byte
				if _, err = io.ReadFull(r, hdrPwd[:]); err == nil {
					pwdLen := int(hdrPwd[0])
					pwdBytes := make([]byte, pwdLen)
					if _, err = io.ReadFull(r, pwdBytes); err == nil {
						usr = string(usrBytes)
						pwd = string(pwdBytes)
					}
				}
			}
		}
	}
	return
}
