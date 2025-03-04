package server_test

import (
	"context"
	"log/slog"
	"net"
	"testing"

	"github.com/linkdata/socks5/client"
	"github.com/linkdata/socks5/server"
	"github.com/linkdata/socks5test"
)

var srvfn = func(ctx context.Context, l net.Listener, username, password string) {
	srv := &server.Server{
		Username: username,
		Password: password,
		Logger:   slog.Default(),
		Debug:    true,
	}
	srv.Serve(ctx, l)
}

var clifn = func(urlstr string) (cd socks5test.ContextDialer, err error) {
	return client.New(urlstr)
}

func TestAuth_None(t *testing.T) {
	socks5test.Auth_None(t, srvfn, clifn)
}

func TestAuth_NoAcceptable(t *testing.T) {
	socks5test.Auth_NoAcceptable(t, srvfn, clifn)
}

func TestAuth_Password(t *testing.T) {
	socks5test.Auth_Password(t, srvfn, clifn)
}

func TestAuth_InvalidPassword(t *testing.T) {
	socks5test.Auth_InvalidPassword(t, srvfn, clifn)
}

func TestAuth_WrongPassword(t *testing.T) {
	socks5test.Auth_WrongPassword(t, srvfn, clifn)
}
