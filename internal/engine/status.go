package engine

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"

	"splitwire/internal/bootstrap"
)

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
	iface, err := a.Configuration()
	if err != nil {
		return true, err
	}
	c := conf.FromDriverConfiguration(iface, &conf.Config{Name: name})
	fmt.Fprintf(w, "  interface %s: listening on port %d\n", name, c.Interface.ListenPort)
	for _, p := range c.Peers {
		fmt.Fprintf(w, "  peer %s\n", p.PublicKey.String())
		if !p.Endpoint.IsEmpty() {
			fmt.Fprintf(w, "    endpoint        %s\n", p.Endpoint.String())
		}
		if p.LastHandshakeTime.IsEmpty() {
			fmt.Fprintf(w, "    last handshake  never\n")
		} else {
			at := time.Unix(0, int64(p.LastHandshakeTime))
			fmt.Fprintf(w, "    last handshake  %s (%s ago)\n", at.Format("2006-01-02 15:04:05"), time.Since(at).Round(time.Second))
		}
		fmt.Fprintf(w, "    transfer        %s received, %s sent\n", byteCount(uint64(p.RxBytes)), byteCount(uint64(p.TxBytes)))
	}
	return true, nil
}

func byteCount(b uint64) string {
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
