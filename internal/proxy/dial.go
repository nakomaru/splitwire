package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// fallbackDelay is the head start a connection attempt gets before the
// next address is tried alongside it (RFC 8305, Happy Eyeballs).
const fallbackDelay = 250 * time.Millisecond

// resolve returns the addresses of host the tunnel has a family for,
// alternating families and starting with IPv6. Host names resolve through
// the tunnel's DNS servers, or through the system's when [Interface] sets
// none.
func (p *Proxy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		var names []string
		if p.dns {
			names, err = p.tnet.LookupContextHost(ctx, host)
		} else {
			names, err = net.DefaultResolver.LookupHost(ctx, host)
		}
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if ip, err := netip.ParseAddr(n); err == nil {
				ips = append(ips, ip.Unmap())
			}
		}
	}
	has4 := p.cfg.TunnelAddress(true).IsValid()
	has6 := p.cfg.TunnelAddress(false).IsValid()
	var v4, v6 []netip.Addr
	for _, ip := range ips {
		switch {
		case ip.Is4() && has4:
			v4 = append(v4, ip)
		case ip.Is6() && has6:
			v6 = append(v6, ip)
		}
	}
	var out []netip.Addr
	for i := 0; i < len(v4) || i < len(v6); i++ {
		if i < len(v6) {
			out = append(out, v6[i])
		}
		if i < len(v4) {
			out = append(out, v4[i])
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s has no address the tunnel can reach", host)
	}
	return out, nil
}

// lookup resolves host to the address a datagram goes to.
func (p *Proxy) lookup(ctx context.Context, host string) (netip.Addr, error) {
	ips, err := p.resolve(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	return ips[0], nil
}

// dial opens a TCP connection to host:port through the tunnel. Each address
// gets fallbackDelay before the next one starts in parallel, and a failed
// attempt starts the next at once; the first connection wins.
func (p *Proxy) dial(ctx context.Context, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("bad port %q", portText)
	}
	ips, err := p.resolve(ctx, host)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		c   net.Conn
		err error
	}
	results := make(chan result, len(ips))
	// drain closes connections that finish after the winner.
	drain := func(n int) {
		go func() {
			for ; n > 0; n-- {
				if r := <-results; r.c != nil {
					r.c.Close()
				}
			}
		}()
	}
	next := time.NewTimer(0)
	defer next.Stop()
	started, pending := 0, 0
	var firstErr error
	for {
		var start <-chan time.Time
		if started < len(ips) {
			start = next.C
		}
		select {
		case <-start:
			ap := netip.AddrPortFrom(ips[started], uint16(port))
			started++
			pending++
			go func() {
				c, err := p.tnet.DialContextTCPAddrPort(ctx, ap)
				if err != nil {
					results <- result{nil, err}
					return
				}
				results <- result{c, nil}
			}()
			next.Reset(fallbackDelay)
		case r := <-results:
			pending--
			if r.err == nil {
				cancel()
				drain(pending)
				return r.c, nil
			}
			if firstErr == nil {
				firstErr = r.err
			}
			if started < len(ips) {
				next.Reset(0)
			} else if pending == 0 {
				return nil, firstErr
			}
		case <-ctx.Done():
			drain(pending)
			return nil, ctx.Err()
		}
	}
}
