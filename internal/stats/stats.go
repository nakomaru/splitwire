// Package stats holds peer statistics shared by the engine, the manager and the tray.
package stats

import (
	"fmt"
	"time"
)

// Peer is the live state of one WireGuard peer.
type Peer struct {
	PublicKey     string
	Endpoint      string
	LastHandshake time.Time // zero when no handshake has completed
	RxBytes       uint64
	TxBytes       uint64
}

// Bytes formats a byte count with binary units.
func Bytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// Ago formats the time since t, or "never" for the zero time.
func Ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return time.Since(t).Round(time.Second).String() + " ago"
}
