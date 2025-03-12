package client_test

import (
	"context"
	"log/slog"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/linkdata/socks5"
	"github.com/linkdata/socks5/client"
	"github.com/linkdata/socks5/server"
	"github.com/linkdata/socks5test"
)

func init() {
	server.ListenerTimeout = time.Millisecond * 10
	server.UDPTimeout = time.Millisecond * 10
}

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
	if x := cli.URL.Host; x != "localhost:1080" {
		t.Error(x)
	}
	if x := cli.URL.User.Username(); x != "u" {
		t.Error(x)
	}
	pwd, _ := cli.URL.User.Password()
	if pwd != "p" {
		t.Error(pwd)
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

func TestClient_FromURL(t *testing.T) {
	u, err := url.Parse("socks5h://localhost:1080")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.FromURL(u, &net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
}
