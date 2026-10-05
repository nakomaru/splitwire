package engine

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"

	"splitwire/internal/bootstrap"
	"splitwire/internal/stats"
)

func peerStats(a *driver.Adapter, name string) ([]stats.Peer, uint16, error) {
	iface, err := a.Configuration()
	if err != nil {
		return nil, 0, err
	}
	c := conf.FromDriverConfiguration(iface, &conf.Config{Name: name})
	peers := make([]stats.Peer, 0, len(c.Peers))
	for _, p := range c.Peers {
		s := stats.Peer{
			PublicKey: p.PublicKey.String(),
			RxBytes:   uint64(p.RxBytes),
			TxBytes:   uint64(p.TxBytes),
		}
		if !p.Endpoint.IsEmpty() {
			s.Endpoint = p.Endpoint.String()
		}
		if !p.LastHandshakeTime.IsEmpty() {
			s.LastHandshake = time.Unix(0, int64(p.LastHandshakeTime))
		}
		peers = append(peers, s)
	}
	return peers, c.Interface.ListenPort, nil
}

// Peers reports the live peer statistics of the tunnel.
func (t *Tunnel) Peers() ([]stats.Peer, error) {
	if t.adapter == nil {
		return nil, nil
	}
	peers, _, err := peerStats(t.adapter, t.cfg.WG.Name)
	return peers, err
}

// PrintAdapterStatus writes peer statistics of a running tunnel. It reports
// false when no adapter of that name exists.
func PrintAdapterStatus(w io.Writer, name string) (bool, error) {
	dll, err := bootstrap.DLLPath()
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(dll); err != nil {
		return false, nil
	}
	if err := bootstrap.LoadWireGuardDLL(dll); err != nil {
		return false, err
	}
	a, err := driver.OpenAdapter(name)
	if err != nil {
		return false, nil
	}
	defer a.Close()
	peers, port, err := peerStats(a, name)
	if err != nil {
		return true, err
	}
	fmt.Fprintf(w, "  interface %s: listening on port %d\n", name, port)
	for _, p := range peers {
		fmt.Fprintf(w, "  peer %s\n", p.PublicKey)
		if p.Endpoint != "" {
			fmt.Fprintf(w, "    endpoint        %s\n", p.Endpoint)
		}
		if p.LastHandshake.IsZero() {
			fmt.Fprintf(w, "    last handshake  never\n")
		} else {
			fmt.Fprintf(w, "    last handshake  %s (%s)\n", p.LastHandshake.Format("2006-01-02 15:04:05"), stats.Ago(p.LastHandshake))
		}
		fmt.Fprintf(w, "    transfer        %s received, %s sent\n", stats.Bytes(p.RxBytes), stats.Bytes(p.TxBytes))
	}
	return true, nil
}
