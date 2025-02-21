package socks5

import (
	"context"
	"errors"
	"net"
)

type client struct {
	srv        *Server
	clientConn net.Conn
}

var ErrUnsupportedCommand = errors.New("unsupported command")
var ErrAuthFailed = errors.New("authentication failed")

func (c *client) serve(ctx context.Context) (err error) {
	var authMethod AuthMethod
	if authMethod, err = c.negotiateAuth(); err == nil {
		if err = c.verifyAuth(authMethod); err == nil {
			err = c.handleRequest(ctx)
		}
	}
	return
}

func (c *client) verifyAuth(authMethod AuthMethod) (err error) {
	if authMethod == PasswordAuth {
		var user, pwd string
		if user, pwd, err = parseClientAuth(c.clientConn); err == nil {
			if user == c.srv.Username && pwd == c.srv.Password {
				_, err = c.clientConn.Write([]byte{1, 0}) // auth success
				return
			}
			err = ErrAuthFailed
		}
		_, _ = c.clientConn.Write([]byte{1, 1}) // auth error
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

func (c *client) negotiateAuth() (authMethod AuthMethod, err error) {
	authMethod = NoAuthRequired
	if c.srv.Username != "" || c.srv.Password != "" {
		authMethod = PasswordAuth
	}
	var authMethods []AuthMethod
	if authMethods, err = readClientGreeting(c.clientConn); err == nil {
		if err = requireAuthMethod(authMethod, authMethods); err == nil {
			_, err = c.clientConn.Write([]byte{Socks5Version, byte(authMethod)})
			return
		}
	}
	_, _ = c.clientConn.Write([]byte{Socks5Version, byte(NoAcceptableAuth)})
	return
}

func (c *client) handleRequest(ctx context.Context) (err error) {
	var req *Request
	replyCode := GeneralFailure
	if req, err = ReadRequest(c.clientConn); err == nil {
		switch req.Cmd {
		case Connect:
			err = c.handleTCP(ctx, req.Addr.String())
		case UdpAssociate:
			err = c.handleUDP(ctx)
		default:
			replyCode = CommandNotSupported
			err = ErrUnsupportedCommand
		}
	}
	return c.fail(replyCode, err)
}

func (c *client) fail(replyCode ReplyCode, err error) error {
	if err != nil {
		rsp := Response{Addr: ZeroAddr, Reply: replyCode}
		buf, _ := rsp.MarshalBinary()
		_, _ = c.clientConn.Write(buf)
	}
	return err
}
