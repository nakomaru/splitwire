package netcfg

import (
	"net/netip"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// defaultRoute finds the default route, on an up interface other than
// exclude, with the lowest combined route and interface metric. Tunnel
// adapters, of type IfTypePropVirtual, never count, so the route found is the
// one outside every VPN tunnel.
func defaultRoute(family winipcfg.AddressFamily, exclude winipcfg.LUID) (*winipcfg.MibIPforwardRow2, error) {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return nil, err
	}
	best := ^uint64(0)
	var pick *winipcfg.MibIPforwardRow2
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 || r.InterfaceLUID == exclude {
			continue
		}
		ifrow, err := r.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp || ifrow.Type == winipcfg.IfTypePropVirtual {
			continue
		}
		ipif, err := r.InterfaceLUID.IPInterface(family)
		if err != nil {
			continue
		}
		if m := uint64(r.Metric) + uint64(ipif.Metric); m < best {
			best = m
			pick = r
		}
	}
	return pick, nil
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

// Link is the default-route interface of one address family outside the
// tunnels. Its LUID is zero when the family has no such route.
type Link struct {
	LUID  winipcfg.LUID
	Index uint32
	// Gateway is the default route's next hop, unspecified on a
	// point-to-point link.
	Gateway netip.Addr
	// Addr is the address outbound connections on the interface use.
	Addr netip.Addr
}

// Physical holds the default-route interfaces outside the tunnels.
type Physical struct {
	V4, V6 Link
}

// Of is the link of addr's family.
func (p Physical) Of(addr netip.Addr) Link {
	if addr.Unmap().Is4() {
		return p.V4
	}
	return p.V6
}

// PhysicalLinks looks up the current physical links, never counting the
// tunnel adapter.
func PhysicalLinks(tunnel winipcfg.LUID) Physical {
	var p Physical
	for _, f := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		r, err := defaultRoute(f, tunnel)
		if err != nil || r == nil {
			continue
		}
		l := Link{LUID: r.InterfaceLUID, Index: r.InterfaceIndex, Gateway: r.NextHop.Addr()}
		if a, err := interfaceAddress(f, r.InterfaceLUID); err == nil {
			l.Addr = a
		}
		if f == windows.AF_INET {
			p.V4 = l
		} else {
			p.V6 = l
		}
	}
	return p
}

// PhysicalWatcher calls onChange with the physical links whenever routes,
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

// WatchPhysical starts a watcher and reports the initial links.
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

	w.last = PhysicalLinks(tunnel)
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
			p := PhysicalLinks(w.tunnel)
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

// Current returns the last reported links.
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
