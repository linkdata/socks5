package server

import (
	"context"
	"net"

	"github.com/linkdata/socks5"
)

type session struct {
	*Server          // server we belong to
	conn    net.Conn // client session connection
}

func (sess *session) serve(ctx context.Context) (err error) {
	var authMethod socks5.AuthMethod
	if authMethod, err = sess.negotiateAuth(); err == nil {
		if err = sess.verifyAuth(authMethod); err == nil {
			err = sess.handleRequest(ctx)
		}
	}
	return
}

func (sess *session) verifyAuth(authMethod socks5.AuthMethod) (err error) {
	if authMethod == socks5.PasswordAuth {
		var user, pwd string
		if user, pwd, err = parseClientAuth(sess.conn); err == nil {
			if user == sess.Server.Username && pwd == sess.Server.Password {
				_, err = sess.conn.Write([]byte{1, byte(socks5.Success)}) // auth success
				return
			}
			err = socks5.ErrAuthFailed
		}
		_, _ = sess.conn.Write([]byte{1, byte(socks5.GeneralFailure)}) // auth error
	}
	return
}

func requireAuthMethod(authMethod socks5.AuthMethod, authMethods []socks5.AuthMethod) (err error) {
	for _, m := range authMethods {
		if m == authMethod {
			return nil
		}
	}
	return socks5.ErrNoAcceptableAuthMethods
}

func (sess *session) negotiateAuth() (authMethod socks5.AuthMethod, err error) {
	authMethod = socks5.NoAuthRequired
	if sess.Server.Username != "" || sess.Server.Password != "" {
		authMethod = socks5.PasswordAuth
	}
	var authMethods []socks5.AuthMethod
	if authMethods, err = readClientGreeting(sess.conn); err == nil {
		if err = requireAuthMethod(authMethod, authMethods); err == nil {
			_, err = sess.conn.Write([]byte{socks5.Socks5Version, byte(authMethod)})
			return
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
