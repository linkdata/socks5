// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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

func TestServer_InvalidCommand(t *testing.T) {
	socks5test.InvalidCommand(t, srvfn, clifn)
}

func TestServer_Logging(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	proxy := server.Server{Logger: slog.Default(), Debug: true}
	proxy.LogDebug("debug")
	proxy.LogInfo("info")
	proxy.LogError("error")
}
