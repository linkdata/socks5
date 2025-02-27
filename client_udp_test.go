package socks5_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func TestClient_UDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ts := newTestServer(ctx, t, false)
	defer ts.close()

	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()

	go func() {
		var buf [32768]byte
		for {
			n, addr, err := packet.ReadFrom(buf[:])
			if err != nil {
				return
			}
			n, err = packet.WriteTo(buf[:n], addr)
			if err != nil {
				t.Error(n, err)
				return
			}
		}
	}()

	conn, err := ts.client.Dial("udp", packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	want := make([]byte, 1024)
	rand.Read(want)
	_, err = conn.Write(want)
	if err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(want))
	_, err = conn.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fail()
	}

	if x := conn.RemoteAddr().String(); x != packet.LocalAddr().String() {
		t.Error(x)
	}

	if x := conn.RemoteAddr().Network(); x != packet.LocalAddr().Network() {
		t.Error(x)
	}
}
