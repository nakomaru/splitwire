// Package logx timestamps log lines as 2006-01-02 15:04:05.000.
package logx

import (
	"bytes"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

const layout = "2006-01-02 15:04:05.000"

type writer struct {
	mu  sync.Mutex
	out []io.Writer
}

func (w *writer) write(p []byte, t time.Time) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	stamp := []byte(t.Format(layout) + " ")
	var buf bytes.Buffer
	for _, line := range bytes.SplitAfter(p, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		buf.Write(stamp)
		buf.Write(line)
		if line[len(line)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	for _, o := range w.out {
		o.Write(buf.Bytes())
	}
	return len(p), nil
}

func (w *writer) Write(p []byte) (int, error) { return w.write(p, time.Now()) }

// WriteWithTimestamp lets WireGuardNT log lines carry the driver's own time
// (nanoseconds since the Unix epoch).
func (w *writer) WriteWithTimestamp(p []byte, ts int64) (int, error) {
	return w.write(p, time.Unix(0, ts))
}

// Setup sends the standard logger to stderr, to extra writers and, when path
// is not empty, to that file as well.
func Setup(path string, extra ...io.Writer) (io.Closer, error) {
	w := &writer{out: append([]io.Writer{os.Stderr}, extra...)}
	var f *os.File
	if path != "" {
		var err error
		f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		w.out = append(w.out, f)
	}
	log.SetFlags(0)
	log.SetOutput(w)
	if f == nil {
		return nopCloser{}, nil
	}
	return f, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// Ring keeps the most recent log lines in memory.
type Ring struct {
	mu    sync.Mutex
	lines []string
	next  int
	full  bool
}

// NewRing keeps up to n lines.
func NewRing(n int) *Ring { return &Ring{lines: make([]string, n)} }

// Write stores each complete line of p.
func (r *Ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, line := range bytes.Split(bytes.TrimRight(p, "\n"), []byte("\n")) {
		r.lines[r.next] = string(line)
		r.next = (r.next + 1) % len(r.lines)
		if r.next == 0 {
			r.full = true
		}
	}
	return len(p), nil
}

// Lines returns the stored lines, oldest first.
func (r *Ring) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		return append([]string(nil), r.lines[:r.next]...)
	}
	return append(append([]string(nil), r.lines[r.next:]...), r.lines[:r.next]...)
}
