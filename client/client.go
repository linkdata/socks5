package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/linkdata/socks5"
)

type Client struct {
	URL                 *url.URL
	ProxyDialer         socks5.ContextDialer // dialer to use when dialing the SOCKS5 server, nil for socks5.DefaultDialer
	socks5.HostLookuper                      // resolver to use, nil for net.DefaultResolver
	LocalResolve        bool                 // if true, always resolve hostnames with HostLookuper
}

var ErrNotContextDialer = errors.New("not a ContextDialer")

// FromURL has the same signature as golang.org/x/net/proxy.FromURL(),
// but it requires that the forward dialer is nil or implements ContextDialer.
// The returned Dialer will implement ContextDialer if there is no error.
func FromURL(u *url.URL, forward socks5.Dialer) (d socks5.Dialer, err error) {
	cd := socks5.DefaultDialer
	if forward != nil {
		err = ErrNotContextDialer
		if fd, ok := forward.(socks5.ContextDialer); ok {
			err = nil
			cd = fd
		}
	}
	if err == nil {
		var cli *Client
		if cli, err = NewFromURL(u); err == nil {
			cli.ProxyDialer = cd
			d = cli
		}
	}
	return
}

func NewFromURL(u *url.URL) (cli *Client, err error) {
	var localResolve bool
	err = socks5.ErrUnsupportedScheme
	switch u.Scheme {
	case "socks5":
		localResolve = true
		fallthrough
	case "socks5h":
		err = nil
	}
	if err == nil {
		cli = &Client{
			URL:          u,
			LocalResolve: localResolve,
		}
	}
	return
}

func New(urlstr string) (cli *Client, err error) {
	var u *url.URL
	if u, err = url.Parse(urlstr); err == nil {
		cli, err = NewFromURL(u)
	}
	return
}

func (cli *Client) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	err = socks5.ErrUnsupportedNetwork
	switch network {
	case "tcp", "tcp4", "tcp6":
		conn, _, err = cli.do(ctx, socks5.CommandConnect, address)
	case "udp", "udp4", "udp6":
		conn, _, err = cli.do(ctx, socks5.CommandAssociate, address)
	}
	return
}

func (cli *Client) Dial(network, address string) (net.Conn, error) {
	return cli.DialContext(context.Background(), network, address)
}

func (cli *Client) ListenContext(ctx context.Context, network, address string) (l net.Listener, err error) {
	err = socks5.ErrUnsupportedNetwork
	switch network {
	case "tcp", "tcp4", "tcp6":
		l, err = cli.bindTCP(ctx, address)
	}
	return
}

func (cli *Client) Listen(network, address string) (l net.Listener, err error) {
	return cli.ListenContext(context.Background(), network, address)
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
		if conn, err = cli.proxyDial(ctx, "tcp", cli.URL.Host); err == nil {
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
		err = socks5.ErrReplyCommandNotSupported
		switch cmd {
		case socks5.CommandConnect:
			if addr, err = cli.connectCommand(proxyconn, socks5.CommandConnect, address); err == nil {
				conn = proxyconn
			}
		case socks5.CommandBind:
			if addr, err = cli.connectCommand(proxyconn, socks5.CommandBind, address); err == nil {
				conn = proxyconn
			}
		case socks5.CommandAssociate:
			if addr, err = cli.connectCommand(proxyconn, socks5.CommandAssociate, ":0"); err == nil {
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
	auths = append(auths, byte(socks5.AuthMethodNone))
	usr := cli.URL.User
	if usr != nil {
		auths = append(auths, byte(socks5.AuthUserPass))
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
				case socks5.AuthNoAcceptable:
					err = socks5.ErrNoAcceptableAuthMethods
				case socks5.AuthMethodNone:
					err = nil
				case socks5.AuthUserPass:
					if usr != nil {
						var b []byte
						b = append(b, socks5.AuthUserPassVersion)
						if b, err = socks5.AppendString(b, usr.Username(), socks5.ErrIllegalUsername); err == nil {
							pwd, _ := usr.Password()
							if b, err = socks5.AppendString(b, pwd, socks5.ErrIllegalPassword); err == nil {
								if _, err = conn.Write(b); err == nil {
									if _, err = io.ReadFull(conn, header[:]); err == nil {
										if err = socks5.MustEqual(header[0], socks5.AuthUserPassVersion, socks5.ErrBadSOCKSAuthVersion); err == nil {
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
			if err = socks5.MustEqual(replyCode, socks5.ReplySuccess, replyCode.ToError()); err == nil {
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

func (cli *Client) proxyDial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	proxyDial := cli.ProxyDialer
	if proxyDial == nil {
		proxyDial = socks5.DefaultDialer
	}
	return proxyDial.DialContext(ctx, network, address)
}
