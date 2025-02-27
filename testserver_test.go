package socks5_test

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/linkdata/socks5"
)

type testServer struct {
	ctx         context.Context
	t           *testing.T
	srvlistener net.Listener
	server      *socks5.Server
	client      *socks5.Client
	srvClosedCh chan struct{}
}

func newTestServer(ctx context.Context, t *testing.T, needauth bool) (ts *testServer) {
	t.Helper()
	var lc net.ListenConfig
	srvlistener, err := lc.Listen(ctx, "tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	ts = &testServer{
		ctx:         ctx,
		t:           t,
		srvlistener: srvlistener,
		server: &socks5.Server{
			Logger: slog.Default(),
			Debug:  true,
		},
		client: &socks5.Client{
			ProxyAddress: srvlistener.Addr().String(),
		},
		srvClosedCh: make(chan struct{}),
	}
	if needauth {
		ts.server.Username = "u"
		ts.server.Password = "p"
	}
	go func() {
		defer close(ts.srvClosedCh)
		ts.server.Serve(ctx, ts.srvlistener)
	}()

	return
}

func (ts *testServer) close() {
	if ts.srvlistener != nil {
		ts.srvlistener.Close()
		ts.srvlistener = nil
		tmr := time.NewTimer(time.Second)
		defer tmr.Stop()
		select {
		case <-tmr.C:
			ts.t.Error("server.Serve did not stop")
		case <-ts.srvClosedCh:
		}
	}
}
