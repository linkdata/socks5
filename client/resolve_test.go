package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func Test_Resolve_Remote(t *testing.T) {
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
	resp, err := httpcli.Get(strings.ReplaceAll(httpsrv.URL, "127.0.0.1", "localhost"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func Test_Resolve_Local(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.Close()

	ts.Client.LocalResolve = true

	httpsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer httpsrv.Close()

	httpcli := httpsrv.Client()
	httpcli.Transport = &http.Transport{DialContext: ts.Client.DialContext}
	resp, err := httpcli.Get(strings.ReplaceAll(httpsrv.URL, "127.0.0.1", "localhost"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
