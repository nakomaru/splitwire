package tray

import (
	"time"

	"splitwire/internal/ipc"
)

// sample is a tunnel's byte counters at one time.
type sample struct {
	at     time.Time
	rx, tx uint64
}

// trafficSpan is how much history the traffic graph shows.
const trafficSpan = 3 * time.Minute

// traffic is a running tunnel's recent samples, since it connected.
type traffic struct {
	since   time.Time
	samples []sample
}

// recordTraffic adds the tunnels' counters to their history and drops the
// history of tunnels that stopped.
func (a *app) recordTraffic(st ipc.Status) {
	now := time.Now()
	up := make(map[string]bool)
	for _, t := range st.Tunnels {
		if t.State != ipc.StateUp || len(t.Peers) == 0 {
			continue
		}
		up[t.Name] = true
		var s sample
		s.at = now
		for _, p := range t.Peers {
			s.rx += p.RxBytes
			s.tx += p.TxBytes
		}
		tr := a.traffic[t.Name]
		if tr == nil || !tr.since.Equal(t.Since) {
			tr = &traffic{since: t.Since}
			a.traffic[t.Name] = tr
		}
		if n := len(tr.samples); n > 0 && now.Sub(tr.samples[n-1].at) < time.Second {
			// Statuses that follow state changes arrive between the
			// periodic ones; one sample per second keeps rates steady.
			continue
		}
		tr.samples = append(tr.samples, s)
		for len(tr.samples) > 1 && now.Sub(tr.samples[0].at) > trafficSpan+5*time.Second {
			tr.samples = tr.samples[1:]
		}
	}
	for name := range a.traffic {
		if !up[name] {
			delete(a.traffic, name)
		}
	}
}

// rate is the transfer per second between two samples.
type rate struct {
	at     time.Time
	rx, tx float64
}

func (tr *traffic) rates() []rate {
	var out []rate
	for i := 1; i < len(tr.samples); i++ {
		a, b := tr.samples[i-1], tr.samples[i]
		dt := b.at.Sub(a.at).Seconds()
		if dt <= 0 || b.rx < a.rx || b.tx < a.tx {
			continue
		}
		out = append(out, rate{b.at, float64(b.rx-a.rx) / dt, float64(b.tx-a.tx) / dt})
	}
	return out
}
