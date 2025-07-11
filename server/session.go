package server

import (
	"context"
	"net"

	"github.com/linkdata/socks5"
)

type session struct {
	*Server           // server we belong to
	conn     net.Conn // client session connection
	username string   // username, empty string if anonymous (AuthMethodNone)
}

func (sess *session) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	var dialer socks5.ContextDialer
	if sess.Server.DialerSelector != nil {
		dialer, err = sess.Server.DialerSelector.SelectDialer(sess.username, network, addr)
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
	if sess.username, err = sess.authenticate(); err == nil {
		err = sess.handleRequest(ctx)
	}
	return
}

func (sess *session) authenticate() (username string, err error) {
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
					username = s
					err = e
					return
				}
			}
		}
	}
	_, _ = sess.conn.Write([]byte{socks5.Socks5Version, byte(socks5.AuthNoAcceptable)})
	return
}

func (sess *session) handleRequest(ctx context.Context) (err error) {
	var req *Request
	if req, err = ReadRequest(sess.conn); err == nil {
		switch req.Cmd {
		case socks5.CommandConnect:
			err = sess.handleCONNECT(ctx, req.Addr.String())
		case socks5.CommandAssociate:
			err = sess.handleASSOCIATE(ctx)
		case socks5.CommandBind:
			err = sess.handleBIND(ctx, req.Addr.String())
		default:
			err = socks5.ErrReplyCommandNotSupported
		}
	}
	return sess.fail(err)
}

func (sess *session) fail(err error) error {
	if err != nil {
		replyCode := socks5.ReplyGeneralFailure
		if re, ok := err.(socks5.ReplyError); ok {
			replyCode = re.ReplyCode
		}
		rsp := Response{Addr: socks5.ZeroAddr, Reply: replyCode}
		buf, _ := rsp.MarshalBinary()
		_, _ = sess.conn.Write(buf)
	}
	return err
}
