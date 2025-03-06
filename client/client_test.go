package client_test

import (
	"context"
	"log/slog"
	"net"
	"testing"

	"github.com/linkdata/socks5"
	"github.com/linkdata/socks5/client"
	"github.com/linkdata/socks5/server"
	"github.com/linkdata/socks5test"
)

var srvfn = func(ctx context.Context, l net.Listener, username, password string) {
	var authenticators []server.Authenticator
	if username != "" {
		authenticators = append(authenticators,
			server.UserPassAuthenticator{
				Credentials: server.StaticCredentials{
					username: password,
				},
			})
	}
	srv := &server.Server{
		Authenticators: authenticators,
		Logger:         slog.Default(),
		Debug:          true,
	}
	srv.Serve(ctx, l)
}

var clifn = func(urlstr string) (cd socks5test.ContextDialer, err error) {
	return client.New(urlstr)
}

func TestClient_New(t *testing.T) {
	cli, err := client.New("socks5://u:p@localhost:1080")
	if err != nil {
		t.Fatal(err)
	}
	if x := cli.ProxyAddress; x != "localhost:1080" {
		t.Error(x)
	}
	if x := cli.ProxyUsername; x != "u" {
		t.Error(x)
	}
	if x := cli.ProxyPassword; x != "p" {
		t.Error(x)
	}
	if !cli.LocalResolve {
		t.Error("!LocalResolve")
	}

	cli, err = client.New("socks5h://localhost:1080")
	if err != nil {
		t.Fatal(err)
	}
	if cli.LocalResolve {
		t.Error("LocalResolve")
	}

	_, err = client.New("http://localhost")
	if err != socks5.ErrUnsupportedScheme {
		t.Error(err)
	}
}
