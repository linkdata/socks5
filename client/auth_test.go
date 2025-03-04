package client_test

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

func Test_Auth_None(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.Close()

	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpsrv.Close()

	httpcli := httpsrv.Client()
	httpcli.Transport = &http.Transport{DialContext: ts.Client.DialContext}
	resp, err := httpcli.Get(httpsrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func Test_Auth_NoAcceptable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, true)
	defer ts.Close()

	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpsrv.Close()

	httpcli := httpsrv.Client()
	httpcli.Transport = &http.Transport{DialContext: ts.Client.DialContext}
	resp, err := httpcli.Get(httpsrv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, socks5.ErrNoAcceptableAuthMethods) {
		t.Error(err)
	}
}

func Test_Auth_Password(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, true)
	defer ts.Close()

	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpsrv.Close()

	ts.Client.ProxyUsername = "u"
	ts.Client.ProxyPassword = "p"

	httpcli := httpsrv.Client()
	httpcli.Transport = &http.Transport{DialContext: ts.Client.DialContext}
	resp, err := httpcli.Get(httpsrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func Test_Auth_InvalidPassword(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, true)
	defer ts.Close()

	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpsrv.Close()

	ts.Client.ProxyUsername = "u"
	ts.Client.ProxyPassword = strings.Repeat("x", 256)

	httpcli := httpsrv.Client()
	httpcli.Transport = &http.Transport{DialContext: ts.Client.DialContext}
	resp, err := httpcli.Get(httpsrv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, socks5.ErrIllegalPassword) {
		t.Error(err)
	}
}

func Test_Auth_WrongPassword(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, true)
	defer ts.Close()

	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpsrv.Close()

	ts.Client.ProxyUsername = "u"
	ts.Client.ProxyPassword = "x"
	httpcli := httpsrv.Client()
	httpcli.Transport = &http.Transport{DialContext: ts.Client.DialContext}
	resp, err := httpcli.Get(httpsrv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if !errors.Is(err, socks5.ErrAuthFailed) {
		t.Error(err)
	}
}
