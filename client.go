package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"
)

type Client struct {
	ProxyAddress  string        // proxy server address
	ProxyDialer   ContextDialer // dialer to use when dialing the proxy, nil for DefaultProxyDialer
	ProxyUsername string        // user name
	ProxyPassword string        // user password
	HostLookuper                // resolver to use, nil for net.DefaultResolver
	LocalResolve  bool          // if true, always resolve hostnames with HostLookuper
}

var DefaultProxyDialer ContextDialer = &net.Dialer{}
var ErrUnsupportedNetwork = errors.New("unsupported network")
var ErrAuthMethodNotSupported = errors.New("auth method not supported")
var ErrIllegalUsername = errors.New("illegal username")
var ErrIllegalPassword = errors.New("illegal password")

func (cli *Client) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	err = ErrUnsupportedNetwork
	switch network {
	case "tcp", "tcp4", "tcp6":
		conn, _, err = cli.do(ctx, ConnectCommand, address)
	case "udp", "udp4", "udp6":
		conn, _, err = cli.do(ctx, AssociateCommand, address)
	}
	return
}

func (cli *Client) Dial(network, address string) (net.Conn, error) {
	return cli.DialContext(context.Background(), network, address)
}

func (cli *Client) Listen(ctx context.Context, network, address string) (l net.Listener, err error) {
	err = ErrUnsupportedNetwork
	switch network {
	case "tcp", "tcp4", "tcp6":
		l, err = cli.bindTCP(ctx, address)
	}
	return
}

func (cli *Client) resolve(ctx context.Context, hostport string) (ipandport string, err error) {
	ipandport = hostport
	if cli.LocalResolve {
		var host, port string
		if host, port, err = net.SplitHostPort(hostport); err == nil && host != "" {
			if _, e := netip.ParseAddr(host); e != nil {
				var addrs []string
				if addrs, err = cli.resolver().LookupHost(ctx, host); err == nil {
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

func (cli *Client) do(ctx context.Context, cmd CommandType, address string) (conn net.Conn, addr Addr, err error) {
	if address, err = cli.resolve(ctx, address); err == nil {
		if conn, err = cli.proxyDial(ctx, "tcp", cli.ProxyAddress); err == nil {
			conn, addr, err = cli.connect(ctx, conn, cmd, address)
		}
	}
	return
}

func (cli *Client) connect(ctx context.Context, proxyconn net.Conn, cmd CommandType, address string) (conn net.Conn, addr Addr, err error) {
	if deadline, ok := ctx.Deadline(); ok && !deadline.IsZero() {
		_ = proxyconn.SetDeadline(deadline)
		defer proxyconn.SetDeadline(time.Time{})
	}
	if err = cli.connectAuth(proxyconn); err == nil {
		err = ErrUnsupportedCommand
		switch cmd {
		case ConnectCommand:
			if addr, err = cli.connectCommand(proxyconn, ConnectCommand, address); err == nil {
				conn = proxyconn
			}
		case BindCommand:
			if addr, err = cli.connectCommand(proxyconn, BindCommand, address); err == nil {
				conn = proxyconn
			}
		case AssociateCommand:
			if addr, err = cli.connectCommand(proxyconn, AssociateCommand, ":0"); err == nil {
				if conn, err = cli.proxyDial(ctx, "udp", addr.String()); err == nil {
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

func (cli *Client) connectAuth(conn net.Conn) (err error) {
	var auths []byte
	auths = append(auths, byte(NoAuthRequired))
	if cli.ProxyUsername != "" {
		auths = append(auths, byte(PasswordAuth))
	}

	var b []byte
	b = append(b, Socks5Version, byte(len(auths)))
	b = append(b, auths...)

	if _, err = conn.Write(b); err == nil {
		var header [2]byte
		if _, err = io.ReadFull(conn, header[:]); err == nil {
			if err = MustEqual(header[0], Socks5Version, ErrVersion); err == nil {
				err = ErrAuthMethodNotSupported
				switch authmethod := AuthMethod(header[1]); authmethod {
				case NoAcceptableAuth:
					err = ErrNoAcceptableAuthMethods
				case NoAuthRequired:
					err = nil
				case PasswordAuth:
					var b []byte
					b = append(b, PasswordAuthVersion)
					if b, err = AppendString(b, cli.ProxyUsername, ErrIllegalUsername); err == nil {
						if b, err = AppendString(b, cli.ProxyPassword, ErrIllegalPassword); err == nil {
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

func (cli *Client) connectCommand(conn net.Conn, cmd CommandType, address string) (proxyaddr Addr, err error) {
	var addr Addr
	if addr, err = AddrFromString(address); err == nil {
		var b []byte
		b = append(b, Socks5Version, byte(cmd), 0)
		if b, err = addr.AppendBinary(b); err == nil {
			if _, err = conn.Write(b); err == nil {
				proxyaddr, err = cli.readReply(conn)
				err = Note(err, "connectCommand")
			}
		}
	}
	return
}

func (cli *Client) readReply(conn net.Conn) (addr Addr, err error) {
	var header [3]byte
	if _, err = io.ReadFull(conn, header[:]); err == nil {
		if err = MustEqual(header[0], Socks5Version, ErrVersion); err == nil {
			replyCode := ReplyCode(header[1])
			if err = MustEqual(replyCode, Success, replyCode.ToError()); err == nil {
				addr, err = ReadAddr(conn)
			}
		}
	}
	return
}

func (cli *Client) resolver() (hl HostLookuper) {
	if hl = cli.HostLookuper; hl == nil {
		hl = net.DefaultResolver
	}
	return
}

func (cli *Client) proxyDial(ctx context.Context, network, address string) (net.Conn, error) {
	proxyDial := cli.ProxyDialer
	if proxyDial == nil {
		proxyDial = DefaultProxyDialer
	}
	return proxyDial.DialContext(ctx, network, address)
}
