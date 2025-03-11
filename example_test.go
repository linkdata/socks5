package socks5_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/linkdata/socks5/client"
	"github.com/linkdata/socks5/server"
)

func Example() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second/10)
	defer cancel()

	listener, err := net.Listen("tcp", ":0")
	if err == nil {
		defer listener.Close()
		srv := server.Server{
			Logger: slog.Default(),
			Authenticators: []server.Authenticator{
				server.NoAuthAuthenticator{},
				server.UserPassAuthenticator{
					Credentials: server.StaticCredentials{
						"joe": "123456",
					},
				},
			},
		}
		go srv.Serve(ctx, listener)
		var cli *client.Client
		if cli, err = client.New("socks5h://joe:123456@" + listener.Addr().String()); err == nil {
			var l net.Listener
			if l, err = cli.ListenContext(ctx, "tcp", ":0"); err == nil {
				defer l.Close()
				slog.Info("client BIND", "address", l.Addr().String())
				fmt.Println("client BIND success")
			}
		}
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		fmt.Printf("failed: %v\n", err)
	}
	// Output:
	// client BIND success
}
