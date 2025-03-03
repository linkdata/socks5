package main

import (
	"context"
	"log/slog"
	"net"

	"github.com/linkdata/socks5"
)

func main() {
	listen, err := net.Listen("tcp", ":1081") // #nosec G102
	if err == nil {
		defer listen.Close()
		proxy := socks5.Server{
			Username: "u",
			Password: "p",
			Logger:   slog.Default(),
			Debug:    true,
		}
		_ = proxy.Serve(context.Background(), listen)
	}
}
