[![build](https://github.com/linkdata/socks5/actions/workflows/build.yml/badge.svg)](https://github.com/linkdata/socks5/actions/workflows/build.yml)
[![coverage](https://coveralls.io/repos/github/linkdata/socks5/badge.svg?branch=main)](https://coveralls.io/github/linkdata/socks5?branch=main)
[![goreport](https://goreportcard.com/badge/github.com/linkdata/socks5)](https://goreportcard.com/report/github.com/linkdata/socks5)
[![Docs](https://godoc.org/github.com/linkdata/socks5?status.svg)](https://godoc.org/github.com/linkdata/socks5)

# socks5

SOCKS5 client and server. Full test coverage provided by https://github.com/linkdata/socks5test.

- [x] Support for the CONNECT command
- [x] Support for the BIND command
- [x] Support for the ASSOCIATE command
- [x] Uses ContextDialer's for easy interoperation with other packages

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
