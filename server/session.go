package server

import (
	"context"
	"net"

	"github.com/linkdata/socks5"
)

type session struct {
	*Server                      // server we belong to
	conn       net.Conn          // client session connection
	username   string            // username, if available
	authMethod socks5.AuthMethod // authentication method
}

func (sess *session) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	var dialer socks5.ContextDialer
	if sess.Server.DialerSelector != nil {
		dialer, err = sess.Server.DialerSelector.Socks5SelectDialer(sess.authMethod, sess.username, network, addr)
	}
	if err == nil {
		if dialer == nil {
			dialer = socks5.DefaultDialer
		}
		conn, err = dialer.DialContext(ctx, network, addr)
	}
	return
}

func (sess *session) serve(ctx context.Context) (err error) {
	if sess.authMethod, sess.username, err = sess.authenticate(); err == nil {
		err = sess.handleRequest(ctx)
	}
	return
}

func (sess *session) authenticate() (authMethod socks5.AuthMethod, username string, err error) {
	var clientAuthMethods []socks5.AuthMethod
	if clientAuthMethods, err = readClientGreeting(sess.conn); err == nil {
		err = socks5.ErrNoAcceptableAuthMethods
		authenticators := sess.Authenticators
		if authenticators == nil {
			authenticators = []Authenticator{NoAuthAuthenticator{}}
		}
		for _, auther := range authenticators {
			for _, clientAuth := range clientAuthMethods {
				if s, e := auther.Socks5Authenticate(sess.conn, clientAuth, sess.conn.RemoteAddr().String()); e != socks5.ErrAuthMethodNotSupported {
					authMethod = clientAuth
					username = s
					err = e
					return
				}
			}
		}
	}
	_, _ = sess.conn.Write([]byte{socks5.Socks5Version, byte(socks5.NoAcceptableAuth)})
	return
}

func (sess *session) handleRequest(ctx context.Context) (err error) {
	var req *Request
	replyCode := socks5.GeneralFailure
	if req, err = ReadRequest(sess.conn); err == nil {
		switch req.Cmd {
		case socks5.ConnectCommand:
			err = sess.handleCONNECT(ctx, req.Addr.String())
		case socks5.AssociateCommand:
			err = sess.handleASSOCIATE(ctx)
		case socks5.BindCommand:
			err = sess.handleBIND(ctx, req.Addr.String())
		default:
			replyCode = socks5.CommandNotSupported
			err = socks5.ErrUnsupportedCommand
		}
	}
	return sess.fail(replyCode, err)
}

func (sess *session) fail(replyCode socks5.ReplyCode, err error) error {
	if err != nil {
		rsp := Response{Addr: socks5.ZeroAddr, Reply: replyCode}
		buf, _ := rsp.MarshalBinary()
		_, _ = sess.conn.Write(buf)
	}
	return err
}
