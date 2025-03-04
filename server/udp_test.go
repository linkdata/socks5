package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/linkdata/socks5"
	"github.com/linkdata/socks5/server"
)

func init() {
	server.UDPTimeout = time.Millisecond * 10
}

func udpEchoServer(conn net.PacketConn) {
	var buf [32768 - 32]byte
	var err error
	slog.Info("udpEchoServer: start", "conn", conn.LocalAddr().String())
	for err == nil {
		var n int
		var addr net.Addr
		if n, addr, err = conn.ReadFrom(buf[:]); err == nil {
			slog.Info("udpEchoServer: readfrom", "conn", conn.LocalAddr().String(), "addr", addr, "data", buf[:n])
			n, err = conn.WriteTo(buf[:n], addr)
			if err != nil {
				panic(err)
			}
			slog.Info("udpEchoServer: writeto", "conn", conn.LocalAddr().String(), "addr", addr, "data", buf[:n])
		}
	}
	slog.Info("udpEchoServer: stop", "conn", conn.LocalAddr().String(), "error", err)
}

func Test_UDP_Single(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.Close()

	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()

	go udpEchoServer(packet)

	conn, err := ts.Client.Dial("udp", packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	want := make([]byte, 16)
	rand.Read(want)
	_, err = conn.Write(want)
	if err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(want))
	_, err = conn.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fail()
	}

	if x := conn.RemoteAddr().String(); x != packet.LocalAddr().String() {
		t.Error(x)
	}

	if x := conn.RemoteAddr().Network(); x != packet.LocalAddr().Network() {
		t.Error(x)
	}
}

func Test_UDP_Multiple(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.Close()

	// backend UDP server which we'll use SOCKS5 to connect to
	newUDPEchoServer := func() net.PacketConn {
		listener, err := net.ListenPacket("udp", "127.0.0.1:0")
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

	conn, err := ts.Client.DialContext(ctx, "udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	pc := conn.(net.PacketConn)

	for i := 0; i < echoServerNumber-1; i++ {
		echoAddress := echoServerListener[i].LocalAddr()
		requestBody := []byte(fmt.Sprintf("Test %d", i))
		slog.Info("echo to", "addr", echoAddress)
		if err != nil {
			t.Fatal(err)
		}
		_, err = pc.WriteTo(requestBody, echoAddress)
		if err != nil {
			t.Fatal(err)
		}
		responseBody := make([]byte, len(requestBody)*2)
		var n int
		var addr net.Addr
		n, addr, err = pc.ReadFrom(responseBody)
		if err != nil {
			t.Fatal(err)
		}
		responseBody = responseBody[:n]
		if x := addr.String(); x != echoAddress.String() {
			t.Error(x)
		}
		if !bytes.Equal(requestBody, responseBody) {
			t.Fatalf("%v got %d: %q want: %q", echoAddress, len(responseBody), responseBody, requestBody)
		}
	}

	time.Sleep(server.UDPTimeout * 2)

	echoServer := echoServerListener[echoServerNumber-1]
	echoAddress := echoServer.LocalAddr()
	requestBody := []byte(fmt.Sprintf("Test %d", echoServerNumber-1))
	_, err = pc.WriteTo(requestBody, echoAddress)
	if err != nil {
		t.Fatal(err)
	}
	responseBody := make([]byte, len(requestBody)*2)
	var n int
	var addr net.Addr
	n, addr, err = pc.ReadFrom(responseBody)
	if err != nil {
		t.Fatal(err)
	}
	responseBody = responseBody[:n]
	if x := addr.String(); x != echoAddress.String() {
		t.Error(x)
	}
	if !bytes.Equal(requestBody, responseBody) {
		t.Errorf("%v got %d: %q want: %q", echoAddress, len(responseBody), responseBody, requestBody)
	}
	conn.Close()
	time.Sleep(server.UDPTimeout)
}

func Test_UDP_InvalidPacket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.Close()

	conn, err := ts.Client.Dial("udp", "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	pktconn := conn.(net.PacketConn)

	addr := socks5.Addr{
		Addr: "!",
		Port: 10000,
		Type: socks5.DomainName,
	}

	_, _ = pktconn.WriteTo([]byte{0}, addr)
}
