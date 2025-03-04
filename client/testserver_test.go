package client_test

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/linkdata/socks5/client"
	"github.com/linkdata/socks5/server"
)

type testServer struct {
	ctx         context.Context
	t           *testing.T
	Srvlistener net.Listener
	Server      *server.Server
	Client      *client.Client
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
		Srvlistener: srvlistener,
		Server: &server.Server{
			Logger: slog.Default(),
			Debug:  true,
		},
		Client: &client.Client{
			ProxyAddress: srvlistener.Addr().String(),
		},
		srvClosedCh: make(chan struct{}),
	}
	if needauth {
		ts.Server.Username = "u"
		ts.Server.Password = "p"
	}
	go func() {
		defer close(ts.srvClosedCh)
		ts.Server.Serve(ctx, ts.Srvlistener)
	}()

	return
}

func (ts *testServer) Close() {
	if ts.Srvlistener != nil {
		ts.Srvlistener.Close()
		ts.Srvlistener = nil
		tmr := time.NewTimer(time.Second)
		defer tmr.Stop()
		select {
		case <-tmr.C:
			ts.t.Error("server.Serve did not stop")
		case <-ts.srvClosedCh:
		}
	}
}
