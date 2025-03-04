// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package server_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/linkdata/socks5"
	"github.com/linkdata/socks5/server"
)

func TestServer_Resolve_InvalidHostname(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.Close()

	conn, err := ts.Client.DialContext(ctx, "tcp", "!:1234")
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, socks5.ErrGeneralFailure) {
		t.Errorf("%v: %#v", err, err)
	}
}

func TestServer_InvalidCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.Srvlistener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write([]byte{socks5.Socks5Version, 0x01, byte(socks5.NoAuthRequired)}) // client hello with no auth
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf) // server hello
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || buf[0] != socks5.Socks5Version || buf[1] != byte(socks5.NoAuthRequired) {
		t.Fatalf("got: %q want: 0x05 0x00", buf[:n])
	}

	targetAddr := socks5.Addr{Type: socks5.DomainName, Addr: "!", Port: 0}
	targetAddrPkt, err := targetAddr.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write(append([]byte{socks5.Socks5Version, 0x00, 0x00}, targetAddrPkt...)) // client reqeust
	if err != nil {
		t.Fatal(err)
	}
	n, err = conn.Read(buf) // server response
	if err != nil {
		t.Fatal(err)
	}
	if n < 3 || !bytes.Equal(buf[:3], []byte{socks5.Socks5Version, byte(socks5.CommandNotSupported), 0x00}) {
		t.Fatalf("got: %q want: 0x05 0x0A 0x00", buf[:n])
	}
}

func TestServer_InvalidUDPPacket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.Srvlistener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write([]byte{socks5.Socks5Version, 0x01, byte(socks5.NoAuthRequired)}) // client hello with no auth
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf) // server hello
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || buf[0] != socks5.Socks5Version || buf[1] != byte(socks5.NoAuthRequired) {
		t.Fatalf("got: %q want: 0x05 0x00", buf[:n])
	}

	targetAddr := socks5.Addr{Type: socks5.DomainName, Addr: "!", Port: 0}
	targetAddrPkt, err := targetAddr.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write(append([]byte{socks5.Socks5Version, 0x00, 0x00}, targetAddrPkt...)) // client reqeust
	if err != nil {
		t.Fatal(err)
	}
	n, err = conn.Read(buf) // server response
	if err != nil {
		t.Fatal(err)
	}
	if n < 3 || !bytes.Equal(buf[:3], []byte{socks5.Socks5Version, byte(socks5.CommandNotSupported), 0x00}) {
		t.Fatalf("got: %q want: 0x05 0x0A 0x00", buf[:n])
	}
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
