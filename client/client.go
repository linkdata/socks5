package client

import (
	"context"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/linkdata/socks5"
)

type Client struct {
	ProxyAddress        string               // proxy server address
	ProxyDialer         socks5.ContextDialer // dialer to use when dialing the proxy, nil for DefaultProxyDialer
	ProxyUsername       string               // user name
	ProxyPassword       string               // user password
	socks5.HostLookuper                      // resolver to use, nil for net.DefaultResolver
	LocalResolve        bool                 // if true, always resolve hostnames with HostLookuper
}

var DefaultProxyDialer socks5.ContextDialer = &net.Dialer{}

func (cli *Client) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	err = socks5.ErrUnsupportedNetwork
	switch network {
	case "tcp", "tcp4", "tcp6":
		conn, _, err = cli.do(ctx, socks5.ConnectCommand, address)
	case "udp", "udp4", "udp6":
		conn, _, err = cli.do(ctx, socks5.AssociateCommand, address)
	}
	return
}

func (cli *Client) Dial(network, address string) (net.Conn, error) {
	return cli.DialContext(context.Background(), network, address)
}

func (cli *Client) Listen(ctx context.Context, network, address string) (l net.Listener, err error) {
	err = socks5.ErrUnsupportedNetwork
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

func (cli *Client) do(ctx context.Context, cmd socks5.CommandType, address string) (conn net.Conn, addr socks5.Addr, err error) {
	if address, err = cli.resolve(ctx, address); err == nil {
		if conn, err = cli.proxyDial(ctx, "tcp", cli.ProxyAddress); err == nil {
			conn, addr, err = cli.connect(ctx, conn, cmd, address)
		}
	}
	return
}

func (cli *Client) connect(ctx context.Context, proxyconn net.Conn, cmd socks5.CommandType, address string) (conn net.Conn, addr socks5.Addr, err error) {
	if deadline, ok := ctx.Deadline(); ok && !deadline.IsZero() {
		_ = proxyconn.SetDeadline(deadline)
		defer proxyconn.SetDeadline(time.Time{})
	}
	if err = cli.connectAuth(proxyconn); err == nil {
		err = socks5.ErrUnsupportedCommand
		switch cmd {
		case socks5.ConnectCommand:
			if addr, err = cli.connectCommand(proxyconn, socks5.ConnectCommand, address); err == nil {
				conn = proxyconn
			}
		case socks5.BindCommand:
			if addr, err = cli.connectCommand(proxyconn, socks5.BindCommand, address); err == nil {
				conn = proxyconn
			}
		case socks5.AssociateCommand:
			if addr, err = cli.connectCommand(proxyconn, socks5.AssociateCommand, ":0"); err == nil {
				if conn, err = cli.proxyDial(ctx, "udp", addr.String()); err == nil {
					if conn, err = NewUDPConn(conn, proxyconn, address); err == nil {
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
	auths = append(auths, byte(socks5.NoAuthRequired))
	if cli.ProxyUsername != "" {
		auths = append(auths, byte(socks5.PasswordAuth))
	}

	var b []byte
	b = append(b, socks5.Socks5Version, byte(len(auths)))
	b = append(b, auths...)

	if _, err = conn.Write(b); err == nil {
		var header [2]byte
		if _, err = io.ReadFull(conn, header[:]); err == nil {
			if err = socks5.MustEqual(header[0], socks5.Socks5Version, socks5.ErrVersion); err == nil {
				err = socks5.ErrAuthMethodNotSupported
				switch authmethod := socks5.AuthMethod(header[1]); authmethod {
				case socks5.NoAcceptableAuth:
					err = socks5.ErrNoAcceptableAuthMethods
				case socks5.NoAuthRequired:
					err = nil
				case socks5.PasswordAuth:
					var b []byte
					b = append(b, socks5.PasswordAuthVersion)
					if b, err = socks5.AppendString(b, cli.ProxyUsername, socks5.ErrIllegalUsername); err == nil {
						if b, err = socks5.AppendString(b, cli.ProxyPassword, socks5.ErrIllegalPassword); err == nil {
							if _, err = conn.Write(b); err == nil {
								if _, err = io.ReadFull(conn, header[:]); err == nil {
									if err = socks5.MustEqual(header[0], socks5.PasswordAuthVersion, socks5.ErrBadSOCKSAuthVersion); err == nil {
										err = socks5.MustEqual(header[1], 0, socks5.ErrAuthFailed)
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

func (cli *Client) connectCommand(conn net.Conn, cmd socks5.CommandType, address string) (proxyaddr socks5.Addr, err error) {
	var addr socks5.Addr
	if addr, err = socks5.AddrFromString(address); err == nil {
		var b []byte
		b = append(b, socks5.Socks5Version, byte(cmd), 0)
		if b, err = addr.AppendBinary(b); err == nil {
			if _, err = conn.Write(b); err == nil {
				proxyaddr, err = cli.readReply(conn)
				err = socks5.Note(err, "connectCommand")
			}
		}
	}
	return
}

func (cli *Client) readReply(conn net.Conn) (addr socks5.Addr, err error) {
	var header [3]byte
	if _, err = io.ReadFull(conn, header[:]); err == nil {
		if err = socks5.MustEqual(header[0], socks5.Socks5Version, socks5.ErrVersion); err == nil {
			replyCode := socks5.ReplyCode(header[1])
			if err = socks5.MustEqual(replyCode, socks5.Success, replyCode.ToError()); err == nil {
				addr, err = socks5.ReadAddr(conn)
			}
		}
	}
	return
}

func (cli *Client) resolver() (hl socks5.HostLookuper) {
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
