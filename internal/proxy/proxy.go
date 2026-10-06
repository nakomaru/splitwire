// Package proxy runs a tunnel in user space as a local SOCKS5 and HTTP
// proxy. The tunnel has its own TCP/IP stack and no network adapter, so any
// number of proxy tunnels run beside each other and beside VPN tunnels, and
// its packets go straight to its endpoint over the physical link.
package proxy

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"splitwire/internal/config"
	"splitwire/internal/netcfg"
	"splitwire/internal/stats"
)

// DefaultMTU is the tunnel MTU when [Interface] sets none.
const DefaultMTU = 1420

// Proxy is a running proxy tunnel.
type Proxy struct {
	cfg  *config.Config
	dev  *device.Device
	bind conn.Bind
	tnet *netstack.Net
	ln   net.Listener
	dns  bool
	// releaseEndpoints gives back the peer endpoints' routes.
	releaseEndpoints func()

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

// Start brings the tunnel up and listens on c.Proxy.
func Start(c *config.Config) (p *Proxy, err error) {
	if !c.Proxy.IsValid() {
		return nil, errors.New("the configuration has no Proxy address")
	}
	var addrs []netip.Addr
	for _, a := range c.WG.Interface.Addresses {
		addrs = append(addrs, a.Addr())
	}
	if len(addrs) == 0 {
		return nil, errors.New("a proxy tunnel needs an [Interface] Address")
	}
	mtu := int(c.WG.Interface.MTU)
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if err := c.WG.ResolveEndpoints(); err != nil {
		return nil, err
	}
	var endpoints []netip.Addr
	for _, peer := range c.WG.Peers {
		if a, err := netip.ParseAddr(peer.Endpoint.Host); err == nil {
			endpoints = append(endpoints, a)
		}
	}

	p = &Proxy{cfg: c, dns: len(c.WG.Interface.DNS) > 0, conns: make(map[net.Conn]struct{})}
	defer func() {
		if err != nil {
			p.Close()
			p = nil
		}
	}()
	// The tunnel's packets go straight to its endpoints, so no VPN tunnel
	// carries them.
	if p.releaseEndpoints, err = netcfg.HoldEndpointRoutes(endpoints); err != nil {
		return nil, fmt.Errorf("route endpoints: %w", err)
	}
	p.ln, err = net.Listen("tcp", c.Proxy.String())
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}
	tdev, tnet, err := netstack.CreateNetTUN(addrs, c.WG.Interface.DNS, mtu)
	if err != nil {
		return nil, err
	}
	p.tnet = tnet
	p.bind = conn.NewDefaultBind()
	prefix := "Proxy " + c.WG.Name + ": "
	p.dev = device.NewDevice(tdev, p.bind, &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   func(format string, args ...any) { log.Printf(prefix+format, args...) },
	})
	if err := p.dev.IpcSet(uapi(c)); err != nil {
		return nil, fmt.Errorf("configure: %w", err)
	}
	if err := p.dev.Up(); err != nil {
		return nil, err
	}
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

// Listen is the proxy's address.
func (p *Proxy) Listen() netip.AddrPort { return p.cfg.Proxy }

// Close stops the proxy, ends its connections and takes the tunnel down.
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closed = true
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
	if p.ln != nil {
		p.ln.Close()
	}
	p.wg.Wait()
	if p.dev != nil {
		p.dev.Close()
	}
	if p.releaseEndpoints != nil {
		p.releaseEndpoints()
	}
}

// track registers a connection for Close to end. It closes c and reports
// false once the proxy is closing.
func (p *Proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		c.Close()
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *Proxy) untrack(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
	c.Close()
}

func (p *Proxy) serve() {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		if !p.track(c) {
			continue
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.untrack(c)
			p.handle(c)
		}()
	}
}

// handshakeTimeout bounds how long a client may take to name its target.
const handshakeTimeout = 30 * time.Second

func (p *Proxy) handle(c net.Conn) {
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == socksVersion {
		p.socks(c, br)
	} else {
		p.serveHTTP(c, br)
	}
}

// Peers reports the live peer statistics.
func (p *Proxy) Peers() ([]stats.Peer, error) {
	text, err := p.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return parsePeers(text), nil
}

func uapi(c *config.Config) string {
	var b strings.Builder
	line := func(k, v string) { b.WriteString(k + "=" + v + "\n") }
	line("private_key", hex.EncodeToString(c.WG.Interface.PrivateKey[:]))
	if c.WG.Interface.ListenPort != 0 {
		line("listen_port", strconv.Itoa(int(c.WG.Interface.ListenPort)))
	}
	line("replace_peers", "true")
	for _, peer := range c.WG.Peers {
		line("public_key", hex.EncodeToString(peer.PublicKey[:]))
		if !peer.PresharedKey.IsZero() {
			line("preshared_key", hex.EncodeToString(peer.PresharedKey[:]))
		}
		if !peer.Endpoint.IsEmpty() {
			line("endpoint", net.JoinHostPort(peer.Endpoint.Host, strconv.Itoa(int(peer.Endpoint.Port))))
		}
		line("persistent_keepalive_interval", strconv.Itoa(int(peer.PersistentKeepalive)))
		line("replace_allowed_ips", "true")
		for _, ip := range peer.AllowedIPs {
			line("allowed_ip", ip.String())
		}
	}
	return b.String()
}

func parsePeers(text string) []stats.Peer {
	var peers []stats.Peer
	var cur *stats.Peer
	var sec, nsec int64
	finish := func() {
		if cur != nil && (sec != 0 || nsec != 0) {
			cur.LastHandshake = time.Unix(sec, nsec)
		}
	}
	for _, l := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			finish()
			key, err := hex.DecodeString(v)
			if err != nil {
				cur = nil
				continue
			}
			peers = append(peers, stats.Peer{PublicKey: base64.StdEncoding.EncodeToString(key)})
			cur, sec, nsec = &peers[len(peers)-1], 0, 0
		}
		if cur == nil {
			continue
		}
		switch k {
		case "endpoint":
			cur.Endpoint = v
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			cur.RxBytes, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			cur.TxBytes, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	finish()
	return peers
}
