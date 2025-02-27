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

	httpcli := httpsrv.Client()
	httpcli.Transport = &http.Transport{DialContext: ts.client.DialContext}
	resp, err := httpcli.Get(httpsrv.URL)
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

	httpcli := httpsrv.Client()
	httpcli.Transport = &http.Transport{DialContext: ts.client.DialContext}
	resp, err := httpcli.Get(httpsrv.URL)
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

	httpcli := httpsrv.Client()
	httpcli.Transport = &http.Transport{DialContext: ts.client.DialContext}
	resp, err := httpcli.Get(httpsrv.URL)
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

	httpcli := httpsrv.Client()
	httpcli.Transport = &http.Transport{DialContext: ts.client.DialContext}
	resp, err := httpcli.Get(httpsrv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, socks5.ErrIllegalPassword) {
		t.Error(err)
	}
}

func TestClient_Auth_WrongPassword(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, true)
	defer ts.close()

	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpsrv.Close()

	ts.client.ProxyUsername = "u"
	ts.client.ProxyPassword = "x"

	httpcli := httpsrv.Client()
	httpcli.Transport = &http.Transport{DialContext: ts.client.DialContext}
	resp, err := httpcli.Get(httpsrv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, socks5.ErrAuthFailed) {
		t.Error(err)
	}
}
