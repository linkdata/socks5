package socks5_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/linkdata/socks5"
)

var testServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	rw.Write([]byte("ok"))
}))

func TestServerAndStdClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := socks5.Server{}
	go proxy.Serve(ctx, listen)

	cli := testServer.Client()
	cli.Transport = &http.Transport{
		Proxy: func(request *http.Request) (*url.URL, error) {
			return url.Parse("socks5://" + listen.Addr().String())
		},
	}
	resp, err := cli.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestServerAndAuthStdClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := socks5.Server{
		Username: "u",
		Password: "p",
	}
	go proxy.Serve(ctx, listen)

	cli := testServer.Client()
	cli.Transport = &http.Transport{
		Proxy: func(request *http.Request) (*url.URL, error) {
			return url.Parse("socks5://u:p@" + listen.Addr().String())
		},
	}
	resp, err := cli.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestServerAndAuthClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	proxy := socks5.Server{
		Username: "u",
		Password: "p",
	}
	go proxy.Serve(ctx, listen)

	dial := socks5.Dialer{ProxyAddress: listen.Addr().String(), ProxyUsername: "u", ProxyPassword: "p"}
	if err != nil {
		t.Fatal(err)
	}
	cli := testServer.Client()
	cli.Transport = &http.Transport{
		DialContext: dial.DialContext,
	}

	resp, err := cli.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

}

func TestServerAndClient(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	proxy := socks5.Server{}
	go proxy.Serve(ctx, listen)

	dial := socks5.Dialer{ProxyAddress: listen.Addr().String(), ProxyUsername: "u", ProxyPassword: "p"}
	if err != nil {
		t.Fatal(err)
	}
	cli := testServer.Client()
	cli.Transport = &http.Transport{
		DialContext: dial.DialContext,
	}

	resp, err := cli.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

}

func TestServerAndClientWithDomain(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	proxy := socks5.Server{}
	go proxy.Serve(ctx, listen)

	dial := socks5.Dialer{ProxyAddress: listen.Addr().String(), ProxyUsername: "u", ProxyPassword: "p"}
	if err != nil {
		t.Fatal(err)
	}
	cli := testServer.Client()
	cli.Transport = &http.Transport{
		DialContext: dial.DialContext,
	}
	resp, err := cli.Get(strings.ReplaceAll(testServer.URL, "127.0.0.1", "localhost"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestServerAndClientWithServerDomain(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	proxy := socks5.Server{}
	go proxy.Serve(ctx, listen)

	dial := socks5.Dialer{ProxyAddress: listen.Addr().String(), ProxyUsername: "u", ProxyPassword: "p"}
	if err != nil {
		t.Fatal(err)
	}
	cli := testServer.Client()
	cli.Transport = &http.Transport{
		DialContext: dial.DialContext,
	}
	resp, err := cli.Get(strings.ReplaceAll(testServer.URL, "127.0.0.1", "localhost"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestUDP2(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	go func() {
		var buf [32768]byte
		for {
			n, addr, err := packet.ReadFrom(buf[:])
			if err != nil {
				return
			}
			n, err = packet.WriteTo(buf[:n], addr)
			if err != nil {
				t.Error(n, err)
				return
			}
		}
	}()

	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	proxy := socks5.Server{}
	go proxy.Serve(ctx, listen)

	dial := socks5.Dialer{ProxyAddress: listen.Addr().String()}
	if err != nil {
		t.Fatal(err)
	}

	conn, err := dial.Dial("udp", packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	want := make([]byte, 1024)
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
}

func TestBind2(t *testing.T) {
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	proxy := socks5.Server{}
	go proxy.Serve(ctx, listen)

	dial := socks5.Dialer{ProxyAddress: listen.Addr().String()}
	if err != nil {
		t.Fatal(err)
	}

	listener, err := dial.Listen(context.Background(), "tcp", ":10000")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(listener, nil)
	time.Sleep(time.Second / 10)
	resp, err := http.Get("http://127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
