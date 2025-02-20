package socks5

import (
	"context"
	"errors"
	"net"
)

type client struct {
	srv           *Server
	clientConn    net.Conn
	udpClientAddr net.Addr
}

var ErrUnsupportedCommand = errors.New("unsupported command")

func (c *client) serve(ctx context.Context) error {
	needAuth := c.srv.Username != "" || c.srv.Password != ""
	authMethod := NoAuthRequired
	if needAuth {
		authMethod = PasswordAuth
	}

	err := parseClientGreeting(c.clientConn, authMethod)
	if err != nil {
		c.clientConn.Write([]byte{Socks5Version, byte(NoAcceptableAuth)})
		return err
	}
	c.clientConn.Write([]byte{Socks5Version, byte(authMethod)})
	if needAuth {
		user, pwd, err := parseClientAuth(c.clientConn)
		if err != nil || user != c.srv.Username || pwd != c.srv.Password {
			c.clientConn.Write([]byte{1, 1}) // auth error
			return err
		}
		c.clientConn.Write([]byte{1, 0}) // auth success
	}

	return c.handleRequest(ctx)
}

func (c *client) handleRequest(ctx context.Context) (err error) {
	var req *Request
	replyCode := GeneralFailure
	if req, err = ReadRequest(c.clientConn); err == nil {
		switch req.Cmd {
		case Connect:
			return c.handleTCP(ctx, req.Addr.String())
		case UdpAssociate:
			return c.handleUDP(ctx)
		default:
			replyCode = CommandNotSupported
			err = ErrUnsupportedCommand
		}
	}
	buf, _ := errorResponse(replyCode).MarshalBinary()
	c.clientConn.Write(buf)
	return
}
