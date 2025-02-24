// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package socks5

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
)

type AuthMethod byte

// Authentication METHODs described in RFC 1928, section 3.
const (
	NoAuthRequired   AuthMethod = 0
	PasswordAuth     AuthMethod = 2
	NoAcceptableAuth AuthMethod = 255
)

// PasswordAuthVersion is the auth version byte described in RFC 1929.
const PasswordAuthVersion = 1

// Socks5Version is the byte that represents the SOCKS version
// in requests.
const Socks5Version byte = 5

// CommandType are the bytes sent in SOCKS5 packets
// that represent the kind of connection the client needs.
type CommandType byte

// The set of valid SOCKS5 commands as described in RFC 1928.
const (
	ConnectCommand   CommandType = 1
	BindCommand      CommandType = 2
	AssociateCommand CommandType = 3
)

// Server is a SOCKS5 proxy server.
type Server struct {
	// Logf optionally specifies the logger to use.
	// If nil, the standard logger is used.
	Logf func(string, ...any)

	// Dialer optionally specifies the ContextDialer to use for outgoing connections.
	// If nil, DefaultDialer will be used, which if not changed is a net.Dialer.
	Dialer ContextDialer

	// Username and Password, if set, are the credential clients must provide.
	Username string
	Password string
}

var DefaultDialer ContextDialer = &net.Dialer{}

func (s *Server) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := s.Dialer
	if dialer == nil {
		dialer = DefaultDialer
	}
	return dialer.DialContext(ctx, network, addr)
}

func (s *Server) logf(format string, args ...any) {
	logf := s.Logf
	if logf == nil {
		logf = log.Printf
	}
	logf(format, args...)
}

// Serve accepts and handles incoming connections on the given listener.
func (s *Server) Serve(ctx context.Context, l net.Listener) (err error) {
	defer l.Close()
	errchan := make(chan error, 1)
	go s.listen(ctx, errchan, l)
	select {
	case <-ctx.Done():
	case err = <-errchan:
	}
	return
}

func (s *Server) listen(ctx context.Context, errchan chan<- error, l net.Listener) {
	defer close(errchan)
	var err error
	for err == nil {
		var clientConn net.Conn
		if clientConn, err = l.Accept(); err == nil {
			go s.startConn(ctx, clientConn)
		}
	}
	errchan <- err
}

func (s *Server) startConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()
	conn := &session{conn: clientConn, srv: s}
	if err := conn.serve(ctx); err != nil {
		s.logf("client connection failed: %v", err)
	}
}

var ErrInvalidPortNumber = errors.New("invalid port number")

func SplitHostPort(hostport string) (host string, port uint16, err error) {
	var portStr string
	if host, portStr, err = net.SplitHostPort(hostport); err == nil {
		var portInt int
		if portInt, err = strconv.Atoi(portStr); err == nil {
			if portInt >= 0 && portInt <= 0xFFFF {
				return host, uint16(portInt), nil
			}
			err = ErrInvalidPortNumber
		}
	}
	return
}

var ErrNoAcceptableAuthMethods = errors.New("no acceptable auth methods")

func readClientGreeting(r io.Reader) (authMethods []AuthMethod, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(r, hdr[:]); err == nil {
		if err = MustEqual(hdr[0], Socks5Version, ErrVersion); err == nil {
			count := int(hdr[1])
			methods := make([]byte, count)
			if _, err = io.ReadFull(r, methods); err == nil {
				for _, m := range methods {
					authMethods = append(authMethods, AuthMethod(m))
				}
			}
		}
	}
	return
}

var ErrBadSOCKSAuthVersion = errors.New("bad SOCKS auth version")

func parseClientAuth(r io.Reader) (usr, pwd string, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(r, hdr[:]); err == nil {
		if err = MustEqual(hdr[0], PasswordAuthVersion, ErrBadSOCKSAuthVersion); err == nil {
			usrLen := int(hdr[1])
			usrBytes := make([]byte, usrLen)
			if _, err = io.ReadFull(r, usrBytes); err == nil {
				var hdrPwd [1]byte
				if _, err = io.ReadFull(r, hdrPwd[:]); err == nil {
					pwdLen := int(hdrPwd[0])
					pwdBytes := make([]byte, pwdLen)
					if _, err = io.ReadFull(r, pwdBytes); err == nil {
						usr = string(usrBytes)
						pwd = string(pwdBytes)
					}
				}
			}
		}
	}
	return
}
