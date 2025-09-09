[![build](https://github.com/linkdata/socks5/actions/workflows/build.yml/badge.svg)](https://github.com/linkdata/socks5/actions/workflows/build.yml)
[![coverage](https://github.com/linkdata/socks5/blob/coverage/main/badge.svg)](https://htmlpreview.github.io/?https://github.com/linkdata/socks5/blob/coverage/main/report.html)
[![goreport](https://goreportcard.com/badge/github.com/linkdata/socks5)](https://goreportcard.com/report/github.com/linkdata/socks5)
[![Docs](https://godoc.org/github.com/linkdata/socks5?status.svg)](https://godoc.org/github.com/linkdata/socks5)

# socks5

SOCKS5 client and server. Full test coverage provided by https://github.com/linkdata/socks5test.

- Support for the CONNECT command
- Support for the BIND command
- Support for the ASSOCIATE command
- Uses ContextDialer's for easy interoperation with other packages
- Only depends on the standard library

## Client

The client support for `net.Listener` includes reporting the bound address and port before calling `Accept()` and
supports multiple concurrent `Accept()` calls, allowing you to reverse-proxy a server using this package.

## Server

The server can listen on multiple listeners concurrently.

The server provides two abstractions to customize it's behavior.

The `Authenticator` interface allows custom authentication methods, and comes with implementations for
anonymous usage (`NoAuthAuthenticator`) or username/password authentication (`UserPassAuthenticator`).

The `DialerSelector` interface allows selecting the `ContextDialer` to use for each outgoing connection
based on authentication method, username, network and address. The default uses `socks5.DefaultDialer`.

## Example

```go
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/linkdata/socks5/client"
	"github.com/linkdata/socks5/server"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second/10)
	defer cancel()

	listener, err := net.Listen("tcp", ":0")
	if err == nil {
		defer listener.Close()
		srv := server.Server{
			Logger: slog.Default(),
			Authenticators: []server.Authenticator{
				server.NoAuthAuthenticator{},
				server.UserPassAuthenticator{
					Credentials: server.StaticCredentials{
						"joe": "123456",
					},
				},
			},
		}
		go srv.Serve(ctx, listener)
		var cli *client.Client
		if cli, err = client.New("socks5h://joe:123456@" + listener.Addr().String()); err == nil {
			var l net.Listener
			if l, err = cli.ListenContext(ctx, "tcp", ":0"); err == nil {
				defer l.Close()
				slog.Info("client BIND", "address", l.Addr().String())
			}
		}
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		slog.Error("failed", "error", err)
	}
}
```
