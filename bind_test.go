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
	listen, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	var server socks5.Server
	go server.Serve(context.Background(), listen)

	dial := &socks5.Dialer{
		ProxyNetwork: "tcp",
		ProxyAddress: listen.Addr().String(),
	}

	listener, err := dial.Listen(context.Background(), "tcp", ":10000")
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
	resp, err := http.Get("http://127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
