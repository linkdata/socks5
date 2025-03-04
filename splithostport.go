package socks5

import (
	"net"
	"strconv"
)

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
