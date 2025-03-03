package socks5_test

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
)

func init() {
	socks5.UDPTimeout = time.Millisecond * 10
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

func TestClient_UDP_Single(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.close()

	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()

	go udpEchoServer(packet)

	conn, err := ts.client.Dial("udp", packet.LocalAddr().String())
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

func TestClient_UDP_Multiple(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.close()

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

	for i := 0; i < echoServerNumber-1; i++ {
		echoAddress := echoServerListener[i].LocalAddr()
		requestBody := []byte(fmt.Sprintf("Test %d", i))
		slog.Info("echo to", "addr", echoAddress)
		pc, err := ts.client.DialContext(ctx, "udp", echoAddress.String())
		if err != nil {
			t.Fatal(err)
		}
		_, err = pc.Write(requestBody)
		if err != nil {
			t.Fatal(err)
		}
		responseBody := make([]byte, len(requestBody)*2)
		var n int
		n, err = pc.Read(responseBody)
		responseBody = responseBody[:n]
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(requestBody, responseBody) {
			t.Fatalf("%v got %d: %q want: %q", echoAddress, len(responseBody), responseBody, requestBody)
		}
	}

	time.Sleep(socks5.UDPTimeout * 2)

	echoServer := echoServerListener[echoServerNumber-1]
	echoAddress := echoServer.LocalAddr()
	requestBody := []byte(fmt.Sprintf("Test %d", echoServerNumber-1))
	pc, err := ts.client.DialContext(ctx, "udp", echoAddress.String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = pc.Write(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	responseBody := make([]byte, len(requestBody)*2)
	var n int
	n, err = pc.Read(responseBody)
	responseBody = responseBody[:n]
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(requestBody, responseBody) {
		t.Fatalf("%v got %d: %q want: %q", echoAddress, len(responseBody), responseBody, requestBody)
	}

	err = pc.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestClient_UDP_InvalidPacket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.close()

	conn, err := ts.client.Dial("udp", "127.0.0.1:10000")
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
