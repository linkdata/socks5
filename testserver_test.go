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
	srvClosedCh chan struct{}
}

func newTestServer(ctx context.Context, t *testing.T) (ts *testServer) {
	t.Helper()
	var err error
	var lc net.ListenConfig
	ts = &testServer{
		ctx: ctx,
		t:   t,
	}
	if ts.srvlistener, err = lc.Listen(ctx, "tcp", ":0"); err != nil {
		t.Fatal(err)
	}
	ts.server = &socks5.Server{
		Logger: slog.Default(),
		Debug:  true,
	}
	ts.srvClosedCh = make(chan struct{})
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
