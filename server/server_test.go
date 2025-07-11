// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server_test

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/linkdata/socks5"
	"github.com/linkdata/socks5/client"
	"github.com/linkdata/socks5/server"
	"github.com/linkdata/socks5test"
)

type dialerselector struct{}

func (dialerselector) SelectDialer(username, network, address string) (cd socks5.ContextDialer, err error) {
	return
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
		DialerSelector: dialerselector{},
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
	srv := server.Server{Logger: slog.Default(), Debug: true}
	srv.LogDebug("debug")
	srv.LogInfo("info")
	srv.LogError("error")
}

func TestServer_DialerSelector(t *testing.T) {
	socks5test.InvalidCommand(t, srvfn, clifn)
}

func TestServer_Serve_CancelContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()
	srv := server.Server{Logger: slog.Default(), Debug: true}
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		srv.Serve(ctx, listen)
	}()
	cancel()
	select {
	case <-time.NewTimer(time.Second).C:
		t.Error("timeout")
	case <-doneCh:
	}
}

func TestServer_Serve_TwoListeners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	listen1, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen1.Close()

	listen2, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen2.Close()

	srv := server.Server{Logger: slog.Default(), Debug: true}
	go srv.Serve(ctx, listen1)
	go srv.Serve(ctx, listen2)

	for ctx.Err() == nil && srv.Serving() != 2 {
		time.Sleep(time.Millisecond)
	}

	listen1.Close()

	for ctx.Err() == nil && srv.Serving() != 1 {
		time.Sleep(time.Millisecond)
	}

	listen2.Close()

	for ctx.Err() == nil && srv.Serving() != 0 {
		time.Sleep(time.Millisecond)
	}

	if ctx.Err() != nil {
		t.Error(ctx.Err())
	}
}
