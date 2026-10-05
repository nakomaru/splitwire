package netcfg

import (
	"net/netip"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// defaultInterface finds the up interface, other than exclude, whose default
// route has the lowest combined route and interface metric.
func defaultInterface(family winipcfg.AddressFamily, exclude winipcfg.LUID) (winipcfg.LUID, error) {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return 0, err
	}
	best := ^uint64(0)
	var luid winipcfg.LUID
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 || r.InterfaceLUID == exclude {
			continue
		}
		ifrow, err := r.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		ipif, err := r.InterfaceLUID.IPInterface(family)
		if err != nil {
			continue
		}
		if m := uint64(r.Metric) + uint64(ipif.Metric); m < best {
			best = m
			luid = r.InterfaceLUID
		}
	}
	return luid, nil
}

// interfaceAddress picks the address outbound connections on luid use: a
// preferred, non-link-local unicast address, favoring IPv6 temporary
// addresses the way source address selection does.
func interfaceAddress(family winipcfg.AddressFamily, luid winipcfg.LUID) (netip.Addr, error) {
	rows, err := winipcfg.GetUnicastIPAddressTable(family)
	if err != nil {
		return netip.Addr{}, err
	}
	var pick netip.Addr
	for i := range rows {
		r := &rows[i]
		if r.InterfaceLUID != luid || r.DadState != winipcfg.DadStatePreferred {
			continue
		}
		a := r.Address.Addr().Unmap()
		if !a.IsValid() {
			continue
		}
		if a.IsLinkLocalUnicast() || a.IsLoopback() {
			continue
		}
		if family == windows.AF_INET6 && r.SuffixOrigin == winipcfg.SuffixOriginRandom {
			return a, nil
		}
		if !pick.IsValid() {
			pick = a
		}
	}
	return pick, nil
}

// Physical holds the addresses of the default-route interface outside the tunnel.
type Physical struct {
	IPv4, IPv6 netip.Addr
}

// PhysicalAddresses looks up the current physical addresses.
func PhysicalAddresses(tunnel winipcfg.LUID) Physical {
	var p Physical
	for _, f := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		luid, err := defaultInterface(f, tunnel)
		if err != nil || luid == 0 {
			continue
		}
		a, err := interfaceAddress(f, luid)
		if err != nil {
			continue
		}
		if f == windows.AF_INET {
			p.IPv4 = a
		} else {
			p.IPv6 = a
		}
	}
	return p
}

// PhysicalWatcher calls onChange with the physical addresses whenever routes,
// interfaces or addresses change and the result differs from the last call.
type PhysicalWatcher struct {
	tunnel   winipcfg.LUID
	onChange func(Physical)

	mu        sync.Mutex
	last      Physical
	callbacks []winipcfg.ChangeCallback
	kick      chan struct{}
	done      chan struct{}
	stopped   sync.WaitGroup
}

// WatchPhysical starts a watcher and reports the initial addresses.
func WatchPhysical(tunnel winipcfg.LUID, onChange func(Physical)) (*PhysicalWatcher, error) {
	w := &PhysicalWatcher{
		tunnel:   tunnel,
		onChange: onChange,
		kick:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	signal := func() {
		select {
		case w.kick <- struct{}{}:
		default:
		}
	}
	cbr, err := winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType, r *winipcfg.MibIPforwardRow2) {
		if r == nil || r.DestinationPrefix.PrefixLength == 0 {
			signal()
		}
	})
	if err != nil {
		return nil, err
	}
	w.callbacks = append(w.callbacks, cbr)
	cba, err := winipcfg.RegisterUnicastAddressChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibUnicastIPAddressRow) {
		signal()
	})
	if err != nil {
		w.Close()
		return nil, err
	}
	w.callbacks = append(w.callbacks, cba)
	cbi, err := winipcfg.RegisterInterfaceChangeCallback(func(winipcfg.MibNotificationType, *winipcfg.MibIPInterfaceRow) {
		signal()
	})
	if err != nil {
		w.Close()
		return nil, err
	}
	w.callbacks = append(w.callbacks, cbi)

	w.last = PhysicalAddresses(tunnel)
	onChange(w.last)
	w.stopped.Add(1)
	go w.loop()
	return w, nil
}

func (w *PhysicalWatcher) loop() {
	defer w.stopped.Done()
	for {
		select {
		case <-w.done:
			return
		case <-w.kick:
			p := PhysicalAddresses(w.tunnel)
			w.mu.Lock()
			changed := p != w.last
			w.last = p
			w.mu.Unlock()
			if changed {
				w.onChange(p)
			}
		}
	}
}

// Current returns the last reported addresses.
func (w *PhysicalWatcher) Current() Physical {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last
}

// Close stops the watcher and waits for a running onChange to return.
func (w *PhysicalWatcher) Close() {
	for _, cb := range w.callbacks {
		cb.Unregister()
	}
	w.callbacks = nil
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	w.stopped.Wait()
}
