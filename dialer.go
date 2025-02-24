package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

type Dialer struct {
	ProxyAddress  string        // proxy server address
	ProxyDialer   ContextDialer // dialer to use when dialing the proxy, nil for DefaultProxyDialer
	ProxyUsername string        // user name
	ProxyPassword string        // user password
	HostLookuper                // resolver to use, nil for net.DefaultResolver
	LocalResolve  bool          // if true, always resolve hostnames with HostLookuper
	DialTimeout   time.Duration // proxy dial timeout, zero for no timeout
}

var DefaultProxyDialer ContextDialer = &net.Dialer{}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	case "tcp", "tcp4", "tcp6":
		return d.do(ctx, ConnectCommand, address)
	case "udp", "udp4", "udp6":
		return d.do(ctx, AssociateCommand, address)
	}
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

var ErrUnsupportedNetwork = errors.New("unsupported network")

func (d *Dialer) Listen(ctx context.Context, network, address string) (l net.Listener, err error) {
	switch network {
	default:
		err = ErrUnsupportedNetwork
	case "tcp", "tcp4", "tcp6":
		l = &listener{ctx: ctx, d: d, address: address}
	}
	return
}

func (d *Dialer) resolve(ctx context.Context, hostport string) (ipandport string, err error) {
	ipandport = hostport
	if d.LocalResolve {
		var host, port string
		if host, port, err = net.SplitHostPort(hostport); err == nil && host != "" {
			if _, e := netip.ParseAddr(host); e != nil {
				var addrs []string
				if addrs, err = d.resolver().LookupHost(ctx, host); err == nil {
					var useip netip.Addr
					for _, s := range addrs {
						if useip, err = netip.ParseAddr(s); err == nil {
							useip = useip.Unmap()
							if useip.Is4() {
								break
							}
						}
					}
					if useip.IsValid() {
						ipandport = net.JoinHostPort(useip.String(), port)
						err = nil
					}
				}
			}
		}
	}
	return
}

func (d *Dialer) do(ctx context.Context, cmd CommandType, address string) (conn net.Conn, err error) {
	if address, err = d.resolve(ctx, address); err == nil {
		if conn, err = d.proxyDial(ctx, "tcp", d.ProxyAddress); err == nil {
			conn, err = d.connect(ctx, conn, cmd, address)
		}
	}
	return
}

func (d *Dialer) connect(ctx context.Context, proxyconn net.Conn, cmd CommandType, address string) (conn net.Conn, err error) {
	if d.DialTimeout != 0 {
		deadline := time.Now().Add(d.DialTimeout)
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}
	if deadline, ok := ctx.Deadline(); ok && !deadline.IsZero() {
		_ = proxyconn.SetDeadline(deadline)
		defer proxyconn.SetDeadline(time.Time{})
	}

	if err = d.connectAuth(proxyconn); err == nil {
		switch cmd {
		default:
			return nil, fmt.Errorf("unsupported command %v", cmd)
		case ConnectCommand:
			if _, err = d.connectCommand(proxyconn, ConnectCommand, address); err == nil {
				conn = proxyconn
			}
		case BindCommand:
			if _, err = d.connectCommand(proxyconn, BindCommand, address); err == nil {
				conn = proxyconn
			}
		case AssociateCommand:
			var proxyaddr Addr
			if proxyaddr, err = d.connectCommand(proxyconn, AssociateCommand, ":0"); err == nil {
				if conn, err = d.proxyDial(ctx, "udp", proxyaddr.String()); err == nil {
					if conn, err = NewUDPConn(conn, address); err == nil {
						go func() {
							defer conn.Close()
							_, _ = io.Copy(io.Discard, proxyconn)
						}()
					}
				}
			}
		}
	}
	return
}

var ErrAuthMethodNotSupported = errors.New("auth method not supported")
var ErrIllegalUsername = errors.New("illegal username")
var ErrIllegalPassword = errors.New("illegal password")

func (d *Dialer) connectAuth(conn net.Conn) (err error) {
	var auths []byte
	auths = append(auths, byte(NoAuthRequired))
	if d.ProxyUsername != "" {
		auths = append(auths, byte(PasswordAuth))
	}

	var b []byte
	b = append(b, Socks5Version, byte(len(auths)))
	b = append(b, auths...)

	if _, err = conn.Write(b); err == nil {
		var header [2]byte
		if _, err = io.ReadFull(conn, header[:]); err == nil {
			if err = MustEqual(header[0], Socks5Version, ErrVersion); err == nil {
				switch authmethod := AuthMethod(header[1]); authmethod {
				default:
					err = ErrAuthMethodNotSupported
				case NoAcceptableAuth:
					err = ErrNoAcceptableAuthMethods
				case NoAuthRequired:
				case PasswordAuth:
					var b []byte
					b = append(b, PasswordAuthVersion)
					if b, err = AppendString(b, d.ProxyUsername, ErrIllegalUsername); err == nil {
						if b, err = AppendString(b, d.ProxyPassword, ErrIllegalPassword); err == nil {
							if _, err = conn.Write(b); err == nil {
								if _, err = io.ReadFull(conn, header[:]); err == nil {
									if err = MustEqual(header[0], PasswordAuthVersion, ErrBadSOCKSAuthVersion); err == nil {
										err = MustEqual(header[1], 0, ErrAuthFailed)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return
}

func (d *Dialer) connectCommand(conn net.Conn, cmd CommandType, address string) (proxyaddr Addr, err error) {
	var addr Addr
	if addr, err = AddrFromString(address); err == nil {
		var b []byte
		b = append(b, Socks5Version, byte(cmd), 0)
		if b, err = addr.AppendBinary(b); err == nil {
			if _, err = conn.Write(b); err == nil {
				proxyaddr, err = d.readReply(conn)
			}
		}
	}
	return
}

func (d *Dialer) readReply(conn net.Conn) (addr Addr, err error) {
	var header [3]byte
	if _, err = io.ReadFull(conn, header[:]); err == nil {
		if err = MustEqual(header[0], Socks5Version, ErrVersion); err == nil {
			if err = MustEqual(ReplyCode(header[1]), Success, ErrUnsupportedCommand); err == nil {
				addr, err = ReadAddr(conn)
			}
		}
	}
	return
}

func (d *Dialer) resolver() (hl HostLookuper) {
	if hl = d.HostLookuper; hl == nil {
		hl = net.DefaultResolver
	}
	return
}

func (d *Dialer) proxyDial(ctx context.Context, network, address string) (net.Conn, error) {
	proxyDial := d.ProxyDialer
	if proxyDial == nil {
		proxyDial = DefaultProxyDialer
	}
	return proxyDial.DialContext(ctx, network, address)
}

type connect struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *connect) RemoteAddr() net.Addr {
	return c.remoteAddr
}
