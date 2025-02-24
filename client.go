package socks5

import (
	"context"
	"errors"
	"net"
)

type session struct {
	srv        *Server
	clientConn net.Conn
}

var ErrUnsupportedCommand = errors.New("unsupported command")
var ErrAuthFailed = errors.New("authentication failed")

func (sess *session) serve(ctx context.Context) (err error) {
	var authMethod AuthMethod
	if authMethod, err = sess.negotiateAuth(); err == nil {
		if err = sess.verifyAuth(authMethod); err == nil {
			err = sess.handleRequest(ctx)
		}
	}
	return
}

func (sess *session) verifyAuth(authMethod AuthMethod) (err error) {
	if authMethod == PasswordAuth {
		var user, pwd string
		if user, pwd, err = parseClientAuth(sess.clientConn); err == nil {
			if user == sess.srv.Username && pwd == sess.srv.Password {
				_, err = sess.clientConn.Write([]byte{1, 0}) // auth success
				return
			}
			err = ErrAuthFailed
		}
		_, _ = sess.clientConn.Write([]byte{1, 1}) // auth error
	}
	return
}

func requireAuthMethod(authMethod AuthMethod, authMethods []AuthMethod) (err error) {
	for _, m := range authMethods {
		if m == authMethod {
			return nil
		}
	}
	return ErrNoAcceptableAuthMethods
}

func (sess *session) negotiateAuth() (authMethod AuthMethod, err error) {
	authMethod = NoAuthRequired
	if sess.srv.Username != "" || sess.srv.Password != "" {
		authMethod = PasswordAuth
	}
	var authMethods []AuthMethod
	if authMethods, err = readClientGreeting(sess.clientConn); err == nil {
		if err = requireAuthMethod(authMethod, authMethods); err == nil {
			_, err = sess.clientConn.Write([]byte{Socks5Version, byte(authMethod)})
			return
		}
	}
	_, _ = sess.clientConn.Write([]byte{Socks5Version, byte(NoAcceptableAuth)})
	return
}

func (sess *session) handleRequest(ctx context.Context) (err error) {
	var req *Request
	replyCode := GeneralFailure
	if req, err = ReadRequest(sess.clientConn); err == nil {
		switch req.Cmd {
		case ConnectCommand:
			err = sess.handleTCP(ctx, req.Addr.String())
		case AssociateCommand:
			err = sess.handleUDP(ctx)
		case BindCommand:
			err = sess.handleBind(ctx, req.Addr.String())
		default:
			replyCode = CommandNotSupported
			err = ErrUnsupportedCommand
		}
	}
	return sess.fail(replyCode, err)
}

func (sess *session) fail(replyCode ReplyCode, err error) error {
	if err != nil {
		rsp := Response{Addr: ZeroAddr, Reply: replyCode}
		buf, _ := rsp.MarshalBinary()
		_, _ = sess.clientConn.Write(buf)
	}
	return err
}
