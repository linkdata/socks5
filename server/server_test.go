// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server_test

import (
	"log/slog"
	"net"
	"testing"

	"github.com/linkdata/socks5/server"
	"github.com/linkdata/socks5test"
)

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
