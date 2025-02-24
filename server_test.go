// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package socks5_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/linkdata/socks5"
	"golang.org/x/net/proxy"
)

func socks5Server(ctx context.Context, listener net.Listener) {
	var server socks5.Server
	err := server.Serve(ctx, listener)
	if err != nil {
		panic(err)
	}
	listener.Close()
}

func backendServer(listener net.Listener) {
	conn, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	conn.Write([]byte("Test"))
	conn.Close()
	listener.Close()
}

func udpEchoServer(conn net.PacketConn) {
	var buf [1024]byte
	n, addr, err := conn.ReadFrom(buf[:])
	if err != nil {
		panic(err)
	}
	_, err = conn.WriteTo(buf[:n], addr)
	if err != nil {
		panic(err)
	}
	conn.Close()
}

func TestRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// backend server which we'll use SOCKS5 to connect to
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	backendServerPort := listener.Addr().(*net.TCPAddr).Port
	go backendServer(listener)

	// SOCKS5 server
	socks5, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	socks5Port := socks5.Addr().(*net.TCPAddr).Port
	go socks5Server(ctx, socks5)

	addr := fmt.Sprintf("localhost:%d", socks5Port)
	socksDialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	addr = fmt.Sprintf("localhost:%d", backendServerPort)
	conn, err := socksDialer.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != "Test" {
		t.Fatalf("got: %q want: Test", buf)
	}

	err = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestTCPInvalidHostname(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// backend server which we'll use SOCKS5 to connect to
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	backendServerPort := listener.Addr().(*net.TCPAddr).Port
	go backendServer(listener)

	// SOCKS5 server
	socks5, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	socks5Port := socks5.Addr().(*net.TCPAddr).Port
	go socks5Server(ctx, socks5)

	addr := fmt.Sprintf("localhost:%d", socks5Port)
	socksDialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	addr = fmt.Sprintf("!:%d", backendServerPort)
	conn, err := socksDialer.Dial("tcp", addr)
	if err == nil {
		conn.Close()
		t.Fatal(err)
	}
}

func TestReadPassword(t *testing.T) {
	// backend server which we'll use SOCKS5 to connect to
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	backendServerPort := ln.Addr().(*net.TCPAddr).Port
	go backendServer(ln)

	socks5ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		socks5ln.Close()
	})
	auth := &proxy.Auth{User: "foo", Password: "bar"}
	go func() {
		s := socks5.Server{Username: auth.User, Password: auth.Password}
		err := s.Serve(context.Background(), socks5ln)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			panic(err)
		}
	}()

	addr := fmt.Sprintf("localhost:%d", socks5ln.Addr().(*net.TCPAddr).Port)

	if d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct); err != nil {
		t.Fatal(err)
	} else {
		if _, err := d.Dial("tcp", addr); err == nil {
			t.Fatal("expected no-auth dial error")
		}
	}

	badPwd := &proxy.Auth{User: "foo", Password: "not right"}
	if d, err := proxy.SOCKS5("tcp", addr, badPwd, proxy.Direct); err != nil {
		t.Fatal(err)
	} else {
		if _, err := d.Dial("tcp", addr); err == nil {
			t.Fatal("expected bad password dial error")
		}
	}

	badUsr := &proxy.Auth{User: "not right", Password: "bar"}
	if d, err := proxy.SOCKS5("tcp", addr, badUsr, proxy.Direct); err != nil {
		t.Fatal(err)
	} else {
		if _, err := d.Dial("tcp", addr); err == nil {
			t.Fatal("expected bad username dial error")
		}
	}

	socksDialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	addr = fmt.Sprintf("localhost:%d", backendServerPort)
	conn, err := socksDialer.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "Test" {
		t.Fatalf("got: %q want: Test", buf)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidUDPCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// SOCKS5 server
	socksrv, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	socks5Port := socksrv.Addr().(*net.TCPAddr).Port
	go socks5Server(ctx, socksrv)

	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", socks5Port))
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

func TestUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	socks5.UDPTimeout = time.Millisecond * 10

	// backend UDP server which we'll use SOCKS5 to connect to
	newUDPEchoServer := func() net.PacketConn {
		listener, err := net.ListenPacket("udp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		go udpEchoServer(listener)
		return listener
	}

	const echoServerNumber = 5
	echoServerListener := make([]net.PacketConn, echoServerNumber)
	for i := 0; i < echoServerNumber; i++ {
		echoServerListener[i] = newUDPEchoServer()
	}
	defer func() {
		for i := 0; i < echoServerNumber; i++ {
			_ = echoServerListener[i].Close()
		}
	}()

	// SOCKS5 server
	socksrv, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	socks5Port := socksrv.Addr().(*net.TCPAddr).Port
	go socks5Server(ctx, socksrv)

	// make a socks5 udpAssociate conn
	newUdpAssociateConn := func() (socks5Conn net.Conn, socks5UDPAddr socks5.Addr) {
		// net/proxy don't support UDP, so we need to manually send the SOCKS5 UDP request
		conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", socks5Port))
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

		targetAddr := socks5.Addr{Type: socks5.Ipv4, Addr: "0.0.0.0", Port: 0}
		targetAddrPkt, err := targetAddr.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		_, err = conn.Write(append([]byte{socks5.Socks5Version, byte(socks5.AssociateCommand), 0x00}, targetAddrPkt...)) // client reqeust
		if err != nil {
			t.Fatal(err)
		}

		n, err = conn.Read(buf) // server response
		if err != nil {
			t.Fatal(err)
		}
		if n < 3 || !bytes.Equal(buf[:3], []byte{socks5.Socks5Version, 0x00, 0x00}) {
			t.Fatalf("got: %q want: 0x05 0x00 0x00", buf[:n])
		}
		udpProxySocksAddr, err := socks5.ReadAddr(bytes.NewReader(buf[3:n]))
		if err != nil {
			t.Fatal(err)
		}

		return conn, udpProxySocksAddr
	}

	conn, udpProxySocksAddr := newUdpAssociateConn()
	defer conn.Close()

	sendUDPAndWaitResponse := func(socks5UDPConn net.Conn, addr socks5.Addr, body []byte) (responseBody []byte) {
		udpPayload, err := (&socks5.UDPPacket{Addr: addr}).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		udpPayload = append(udpPayload, body...)
		_, err = socks5UDPConn.Write(udpPayload)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1024)
		n, err := socks5UDPConn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		var req *socks5.UDPPacket
		req, err = socks5.ParseUDPPacket(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		return req.Body
	}

	udpProxyAddr, err := net.ResolveUDPAddr("udp", udpProxySocksAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	socks5UDPConn, err := net.DialUDP("udp", nil, udpProxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer socks5UDPConn.Close()

	for i := 0; i < echoServerNumber-1; i++ {
		port := echoServerListener[i].LocalAddr().(*net.UDPAddr).Port
		addr := socks5.Addr{Type: socks5.Ipv4, Addr: "127.0.0.1", Port: uint16(port)}
		requestBody := []byte(fmt.Sprintf("Test %d", i))
		responseBody := sendUDPAndWaitResponse(socks5UDPConn, addr, requestBody)
		if !bytes.Equal(requestBody, responseBody) {
			t.Fatalf("got: %q want: %q", responseBody, requestBody)
		}
	}

	time.Sleep(socks5.UDPTimeout * 2)

	port := echoServerListener[echoServerNumber-1].LocalAddr().(*net.UDPAddr).Port
	addr := socks5.Addr{Type: socks5.Ipv4, Addr: "127.0.0.1", Port: uint16(port)}
	requestBody := []byte(fmt.Sprintf("Test %d", echoServerNumber-1))
	responseBody := sendUDPAndWaitResponse(socks5UDPConn, addr, requestBody)
	if !bytes.Equal(requestBody, responseBody) {
		t.Fatalf("got: %q want: %q", responseBody, requestBody)
	}
}

func Test_SplitHostPort(t *testing.T) {
	host, port, err := socks5.SplitHostPort("host:10")
	if err != nil {
		t.Error(err)
	}
	if host != "host" {
		t.Error(host)
	}
	if port != 10 {
		t.Error(port)
	}
	_, _, err = socks5.SplitHostPort("host:-1")
	if err != socks5.ErrInvalidPortNumber {
		t.Error(err)
	}
}
