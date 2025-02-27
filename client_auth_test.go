package socks5_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/linkdata/socks5"
)

func TestClient_Auth_None(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.close()

	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpsrv.Close()

	tp := &http.Transport{DialContext: ts.client.DialContext}
	httpClient := http.Client{Transport: tp}
	resp, err := httpClient.Get(httpsrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestClient_Auth_NoAcceptable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, true)
	defer ts.close()

	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpsrv.Close()

	tp := &http.Transport{DialContext: ts.client.DialContext}
	httpClient := http.Client{Transport: tp}
	resp, err := httpClient.Get(httpsrv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, socks5.ErrNoAcceptableAuthMethods) {
		t.Error(err)
	}
}

func TestClient_Auth_Password(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, true)
	defer ts.close()

	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpsrv.Close()

	ts.client.ProxyUsername = "u"
	ts.client.ProxyPassword = "p"

	tp := &http.Transport{DialContext: ts.client.DialContext}
	httpClient := http.Client{Transport: tp}
	resp, err := httpClient.Get(httpsrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestClient_Auth_InvalidPassword(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, true)
	defer ts.close()

	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpsrv.Close()

	ts.client.ProxyUsername = "u"
	ts.client.ProxyPassword = strings.Repeat("x", 256)

	tp := &http.Transport{DialContext: ts.client.DialContext}
	httpClient := http.Client{Transport: tp}
	resp, err := httpClient.Get(httpsrv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, socks5.ErrIllegalPassword) {
		t.Error(err)
	}
}
