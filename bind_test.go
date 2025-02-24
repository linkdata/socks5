package socks5_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/linkdata/socks5"
)

func TestBind(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	var server socks5.Server
	go server.Serve(ctx, listen)

	dial := &socks5.Dialer{ProxyAddress: listen.Addr().String()}

	listener, err := dial.Listen(ctx, "tcp", ":10001")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		httperr := http.Serve(listener, nil)
		if httperr != nil {
			t.Error(httperr)
		}
	}()

	time.Sleep(time.Second / 10)

	resp, err := http.Get("http://127.0.0.1:10001")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
