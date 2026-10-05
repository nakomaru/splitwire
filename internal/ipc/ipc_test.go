package ipc

import (
	"context"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"splitwire/internal/stats"
)

func TestRoundTrip(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	const name = `\\.\pipe\splitwire-test`
	ln, err := winio.ListenPipe(name, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + user.User.Sid.String() + ")",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		conn := NewConn(c)
		defer conn.Close()
		var req Request
		if conn.Receive(&req) != nil {
			return
		}
		if req.Op != OpUp {
			conn.Send(Reply{Error: "bad op " + req.Op})
			return
		}
		conn.Send(Reply{Status: &Status{
			State: StateUp, Tunnel: req.Name, ConfigHash: ConfigHash(req.Config),
			Peers: []stats.Peer{{PublicKey: "k", RxBytes: 5}},
		}})
		conn.Receive(&req)
		conn.Send(Reply{Error: "boom"})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := winio.DialPipeContext(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	conn := NewConn(c)
	defer conn.Close()
	rep, err := conn.Call(Request{Op: OpUp, Name: "home", Config: "text"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status.Tunnel != "home" || rep.Status.ConfigHash != ConfigHash("text") || rep.Status.Peers[0].RxBytes != 5 {
		t.Fatalf("reply %+v", rep.Status)
	}
	if _, err := conn.Call(Request{Op: OpStatus}); err == nil || err.Error() != "boom" {
		t.Fatalf("error reply became %v", err)
	}
}
