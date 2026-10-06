package netcfg

import (
	"errors"
	"log"
	"net/netip"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Endpoint routes are host routes that send tunnel endpoints out of the
// physical link, so one tunnel's routes, such as a default route, never
// carry another tunnel's encrypted packets. Tunnels sharing an endpoint share
// its route, and the routes follow the physical link as networks change.
var endpointRoutes struct {
	// life serializes starting and stopping the watcher.
	life    sync.Mutex
	watcher *PhysicalWatcher

	mu   sync.Mutex
	phys Physical
	held map[netip.Addr]int
	// routes are the installed routes, by endpoint.
	routes map[netip.Addr]endpointRoute
}

type endpointRoute struct {
	luid    winipcfg.LUID
	gateway netip.Addr
}

// HoldEndpointRoutes routes addrs out of the physical link until release
// is called. Routes need administrator rights; without them, the endpoints
// follow the system routes.
func HoldEndpointRoutes(addrs []netip.Addr) (release func(), err error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		if len(addrs) > 0 {
			log.Printf("Without administrator rights, the tunnel's packets follow the system routes, through any VPN tunnel")
		}
		return func() {}, nil
	}
	er := &endpointRoutes
	er.life.Lock()
	defer er.life.Unlock()
	if er.watcher == nil {
		er.held = make(map[netip.Addr]int)
		er.routes = make(map[netip.Addr]endpointRoute)
		w, err := WatchPhysical(0, repointEndpoints)
		if err != nil {
			return nil, err
		}
		er.watcher = w
	}
	var held []netip.Addr
	er.mu.Lock()
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() {
			continue
		}
		held = append(held, a)
		er.held[a]++
		if er.held[a] == 1 {
			routeEndpointLocked(a)
		}
	}
	er.mu.Unlock()
	return func() { releaseEndpoints(held) }, nil
}

func releaseEndpoints(addrs []netip.Addr) {
	er := &endpointRoutes
	er.life.Lock()
	defer er.life.Unlock()
	er.mu.Lock()
	for _, a := range addrs {
		er.held[a]--
		if er.held[a] <= 0 {
			delete(er.held, a)
			unrouteEndpointLocked(a)
		}
	}
	idle := len(er.held) == 0
	er.mu.Unlock()
	if idle && er.watcher != nil {
		er.watcher.Close()
		er.watcher = nil
	}
}

// repointEndpoints moves every endpoint route to the current physical link.
func repointEndpoints(p Physical) {
	er := &endpointRoutes
	er.mu.Lock()
	defer er.mu.Unlock()
	er.phys = p
	for a := range er.held {
		unrouteEndpointLocked(a)
		routeEndpointLocked(a)
	}
}

func routeEndpointLocked(a netip.Addr) {
	er := &endpointRoutes
	link := er.phys.Of(a)
	if link.LUID == 0 || a.IsLoopback() || reachedDirectly(a) {
		return
	}
	dest := netip.PrefixFrom(a, a.BitLen())
	if err := link.LUID.AddRoute(dest, link.Gateway, 0); err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		log.Printf("Warning: route endpoint %s out of the physical link: %v", a, err)
		return
	}
	er.routes[a] = endpointRoute{luid: link.LUID, gateway: link.Gateway}
}

func unrouteEndpointLocked(a netip.Addr) {
	er := &endpointRoutes
	r, ok := er.routes[a]
	if !ok {
		return
	}
	delete(er.routes, a)
	if err := r.luid.DeleteRoute(netip.PrefixFrom(a, a.BitLen()), r.gateway); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
		log.Printf("Warning: remove the route of endpoint %s: %v", a, err)
	}
}

// reachedDirectly reports whether a route other than a default route, on an
// interface other than a tunnel adapter, covers a. Such an endpoint, on the
// local network or a virtual machine's network, needs no host route.
func reachedDirectly(a netip.Addr) bool {
	family := winipcfg.AddressFamily(windows.AF_INET6)
	if a.Is4() {
		family = windows.AF_INET
	}
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return false
	}
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength == 0 || !r.DestinationPrefix.Prefix().Contains(a) {
			continue
		}
		if _, ours := endpointRoutes.routes[a]; ours && r.DestinationPrefix.PrefixLength == uint8(a.BitLen()) {
			continue
		}
		if ifrow, err := r.InterfaceLUID.Interface(); err == nil && ifrow.Type != winipcfg.IfTypePropVirtual {
			return true
		}
	}
	return false
}
