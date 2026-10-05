// Package ipc is the protocol between the splitwire manager service and its
// clients: newline-delimited JSON over the named pipe \\.\pipe\splitwire.
package ipc

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"

	"splitwire/internal/stats"
)

// PipeName is the manager's pipe.
const PipeName = `\\.\pipe\splitwire`

// ServiceName is the manager service.
const ServiceName = "splitwire"

// Operations.
const (
	OpStatus    = "status"    // reply with the current Status
	OpUp        = "up"        // bring up Name from Config, replacing any running tunnel
	OpDown      = "down"      // take the running tunnel down
	OpWatch     = "watch"     // stream a Status on every change and periodically while up
	OpAutostart = "autostart" // bring up Name from Config at boot; an empty Name clears it
	OpLog       = "log"       // reply with recent manager log lines
)

// Request is one client request.
type Request struct {
	Op     string
	Name   string `json:",omitempty"`
	Config string `json:",omitempty"`
}

// Tunnel states.
const (
	StateDown     = "down"
	StateStarting = "starting"
	StateUp       = "up"
	StateStopping = "stopping"
	StateError    = "error"
)

// Status describes the manager's tunnel.
type Status struct {
	State  string
	Tunnel string `json:",omitempty"`
	Mode   string `json:",omitempty"`
	Apps   int    `json:",omitempty"`
	// ConfigHash identifies the configuration text the tunnel runs, so a
	// client can tell when the file on disk has changed since.
	ConfigHash string       `json:",omitempty"`
	Since      time.Time    `json:",omitempty"`
	Error      string       `json:",omitempty"`
	Peers      []stats.Peer `json:",omitempty"`
	Autostart  string       `json:",omitempty"`
}

// ConfigHash identifies configuration text.
func ConfigHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:8])
}

// Reply answers a request.
type Reply struct {
	Error  string   `json:",omitempty"`
	Status *Status  `json:",omitempty"`
	Log    []string `json:",omitempty"`
}

// Conn is a client connection.
type Conn struct {
	c   net.Conn
	r   *bufio.Reader
	enc *json.Encoder
}

// Dial connects to the manager.
func Dial(ctx context.Context) (*Conn, error) {
	c, err := winio.DialPipeContext(ctx, PipeName)
	if err != nil {
		return nil, err
	}
	return NewConn(c), nil
}

// NewConn wraps a pipe connection.
func NewConn(c net.Conn) *Conn {
	return &Conn{c: c, r: bufio.NewReaderSize(c, 64<<10), enc: json.NewEncoder(c)}
}

// Close closes the connection.
func (c *Conn) Close() error { return c.c.Close() }

// Send writes a value as one line.
func (c *Conn) Send(v any) error { return c.enc.Encode(v) }

// Receive reads one line into v.
func (c *Conn) Receive(v any) error {
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

// Call sends a request and waits for its reply. A reply carrying an error
// becomes the returned error.
func (c *Conn) Call(req Request) (*Reply, error) {
	if err := c.Send(req); err != nil {
		return nil, err
	}
	var rep Reply
	if err := c.Receive(&rep); err != nil {
		return nil, err
	}
	if rep.Error != "" {
		return &rep, fmt.Errorf("%s", rep.Error)
	}
	return &rep, nil
}

// Call dials the manager for a single request.
func Call(ctx context.Context, req Request) (*Reply, error) {
	c, err := Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Call(req)
}

// Listen opens the manager's pipe for SYSTEM, Administrators and the given user.
func Listen(userSID string) (net.Listener, error) {
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if userSID != "" {
		sddl += "(A;;GRGW;;;" + userSID + ")"
	}
	return winio.ListenPipe(PipeName, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
}
