package client_test

import (
	"context"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/linkdata/socks5/client"
)

func Test_Listen_SingleRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.Close()

	client := client.Client{ProxyAddress: ts.Srvlistener.Addr().String()}

	listenPort := ":" + strconv.Itoa(10000+rand.IntN(1000))
	listener, err := client.Listen(ctx, "tcp", listenPort)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	listenAddr := listener.Addr()
	if listenAddr == nil {
		t.Fatal("listener.Addr() returned nil")
	}

	errCh := make(chan error)
	go func() {
		defer close(errCh)
		errCh <- http.Serve(listener, nil)
	}()

	resp, err := http.Get("http://" + listenAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	err = listener.Close()
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-time.NewTimer(time.Second).C:
		t.Error("http.Serve did not stop")
	case err = <-errCh:
		if err != nil {
			t.Log(err)
		}
	}

	// wait until we get "connection refused"
	for range 10 {
		resp, err = http.Get("http://" + listenAddr.String())
		if err == nil {
			resp.Body.Close()
		}
		if strings.Contains(err.Error(), "connection refused") {
			return
		}
	}
	t.Error(err)
}

func Test_Listen_SerialRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.Close()

	client := client.Client{ProxyAddress: ts.Srvlistener.Addr().String()}

	listener, err := client.Listen(ctx, "tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	errCh := make(chan error)
	go func() {
		defer close(errCh)
		errCh <- http.Serve(listener, nil)
	}()

	for i := range 10 {
		resp, err := http.Get("http://" + listener.Addr().String())
		if err != nil {
			t.Error(i, err)
		} else {
			resp.Body.Close()
		}
	}

	err = listener.Close()
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-time.NewTimer(time.Second).C:
		t.Error("http.Serve did not stop")
	case err = <-errCh:
		if err != nil {
			t.Log(err)
		}
	}
}

func Test_Listen_ParallelRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.Close()

	client := client.Client{ProxyAddress: ts.Srvlistener.Addr().String()}

	listener, err := client.Listen(ctx, "tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	errCh := make(chan error)
	go func() {
		defer close(errCh)
		errCh <- http.Serve(listener, nil)
	}()

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get("http://" + listener.Addr().String())
			if err != nil {
				t.Error(i, err)
			} else {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()

	err = listener.Close()
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-time.NewTimer(time.Second).C:
		t.Error("http.Serve did not stop")
	case err = <-errCh:
		if err != nil {
			t.Log(err)
		}
	}
}
