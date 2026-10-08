package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// SOCKS5 protocol values (RFC 1928).
const (
	socksVersion = 5

	methodNone         = 0
	methodNoAcceptable = 0xff

	cmdConnect      = 1
	cmdUDPAssociate = 3

	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4

	repSuccess             = 0
	repFailure             = 1
	repNetworkUnreachable  = 3
	repHostUnreachable     = 4
	repConnectionRefused   = 5
	repCommandNotSupported = 7
	repAddressNotSupported = 8
)

// dialTimeout bounds connecting to a target through the tunnel.
const dialTimeout = 30 * time.Second

func (p *Proxy) socks(c net.Conn, br *bufio.Reader) {
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	method := byte(methodNoAcceptable)
	for _, m := range methods {
		if m == methodNone {
			method = methodNone
		}
	}
	if _, err := c.Write([]byte{socksVersion, method}); err != nil || method != methodNone {
		return
	}

	var req [3]byte
	if _, err := io.ReadFull(br, req[:]); err != nil || req[0] != socksVersion {
		return
	}
	host, port, err := readAddr(br)
	if err != nil {
		reply(c, repAddressNotSupported, netip.AddrPort{})
		return
	}
	switch req[1] {
	case cmdConnect:
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		target, err := p.dial(ctx, net.JoinHostPort(host, strconv.Itoa(int(port))))
		cancel()
		if err != nil {
			reply(c, replyCode(err), netip.AddrPort{})
			return
		}
		bound, _ := netip.ParseAddrPort(target.LocalAddr().String())
		if reply(c, repSuccess, bound) != nil {
			target.Close()
			return
		}
		c.SetDeadline(time.Time{})
		p.pipe(c, br, target)
	case cmdUDPAssociate:
		p.associate(c, br)
	default:
		reply(c, repCommandNotSupported, netip.AddrPort{})
	}
}

// readAddr reads an ATYP-prefixed address and port.
func readAddr(r io.Reader) (string, uint16, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, err
	}
	var host string
	switch atyp[0] {
	case atypIPv4, atypIPv6:
		b := make([]byte, 4)
		if atyp[0] == atypIPv6 {
			b = make([]byte, 16)
		}
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		ip, _ := netip.AddrFromSlice(b)
		host = ip.String()
	case atypDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", 0, err
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, errors.New("unknown address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(port[:]), nil
}

// appendAddr appends an ATYP-prefixed address and port.
func appendAddr(b []byte, ap netip.AddrPort) []byte {
	ip := ap.Addr().Unmap()
	switch {
	case ip.Is4():
		a := ip.As4()
		b = append(append(b, atypIPv4), a[:]...)
	case ip.Is6():
		a := ip.As16()
		b = append(append(b, atypIPv6), a[:]...)
	default:
		b = append(b, atypIPv4, 0, 0, 0, 0)
	}
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

func reply(c net.Conn, code byte, bound netip.AddrPort) error {
	_, err := c.Write(appendAddr([]byte{socksVersion, code, 0}, bound))
	return err
}

func replyCode(err error) byte {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return repConnectionRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return repNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, context.DeadlineExceeded):
		return repHostUnreachable
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return repHostUnreachable
	}
	return repFailure
}

// pipe copies between the client and the target until both directions
// end. An end of stream passes on as a half close; an error, or a
// direction idle for halfCloseIdle after the other has ended, ends both.
func (p *Proxy) pipe(c net.Conn, br *bufio.Reader, target net.Conn) {
	if !p.track(target) {
		return
	}
	defer p.untrack(target)
	var half atomic.Bool
	// ended passes on src's end of stream to dst and starts the idle limit
	// on the other direction, whose blocked read or write the new deadlines
	// also cut short. An error ends both connections.
	ended := func(err error, dst, src net.Conn) {
		if err != nil {
			c.Close()
			target.Close()
			return
		}
		closeWrite(dst)
		half.Store(true)
		limit := time.Now().Add(halfCloseIdle)
		dst.SetReadDeadline(limit)
		src.SetWriteDeadline(limit)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ended(relay(target, c, br, &half), target, c)
	}()
	ended(relay(c, target, target, &half), c, target)
	<-done
}

// halfCloseIdle is how long a connection may go without traffic once one
// direction has ended. A client that half closes and a client that closed
// and left look alike to the proxy, so a silent target would otherwise hold
// the connection forever.
var halfCloseIdle = time.Minute

// relay copies r, which reads src, to dst until r ends, and returns nil at
// its end of stream. Once half is set, each read and write must finish
// within halfCloseIdle.
func relay(dst, src net.Conn, r io.Reader, half *atomic.Bool) error {
	buf := make([]byte, 32<<10)
	for {
		if half.Load() {
			src.SetReadDeadline(time.Now().Add(halfCloseIdle))
		}
		n, err := r.Read(buf)
		if n > 0 {
			if half.Load() {
				dst.SetWriteDeadline(time.Now().Add(halfCloseIdle))
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		c.Close()
	}
}

// associate relays UDP datagrams for one client until its control
// connection closes. Only datagrams from the client's own address are
// relayed, and replies go back to the address of its latest datagram.
func (p *Proxy) associate(c net.Conn, br *bufio.Reader) {
	clientIP, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	localIP, _ := netip.ParseAddrPort(c.LocalAddr().String())
	relay, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(localIP.Addr(), 0)))
	if err != nil {
		reply(c, repFailure, netip.AddrPort{})
		return
	}
	defer relay.Close()
	bound, _ := netip.ParseAddrPort(relay.LocalAddr().String())
	if reply(c, repSuccess, bound) != nil {
		return
	}
	c.SetDeadline(time.Time{})

	a := &association{p: p, relay: relay, clientIP: clientIP.Addr().Unmap()}
	defer a.close()
	go func() {
		io.Copy(io.Discard, br)
		relay.Close()
	}()
	a.fromClient()
}

type association struct {
	p        *Proxy
	relay    *net.UDPConn
	clientIP netip.Addr

	mu     sync.Mutex
	client netip.AddrPort
	v4, v6 *gonet.UDPConn
	closed bool
}

func (a *association) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	for _, u := range []*gonet.UDPConn{a.v4, a.v6} {
		if u != nil {
			u.Close()
		}
	}
}

// socket returns the tunnel socket for the address family, opening it and
// its reply reader on first use.
func (a *association) socket(v4 bool) (*gonet.UDPConn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, net.ErrClosed
	}
	slot := &a.v6
	if v4 {
		slot = &a.v4
	}
	if *slot == nil {
		local := a.p.cfg.TunnelAddress(v4)
		if !local.IsValid() {
			return nil, errors.New("the tunnel has no address of that family")
		}
		u, err := a.p.tnet.ListenUDPAddrPort(netip.AddrPortFrom(local, 0))
		if err != nil {
			return nil, err
		}
		*slot = u
		go a.toClient(u)
	}
	return *slot, nil
}

func (a *association) fromClient() {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := a.relay.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if from.Addr().Unmap() != a.clientIP || n < 4 || buf[2] != 0 {
			continue // foreign sender, short header or a fragment
		}
		a.mu.Lock()
		a.client = from
		a.mu.Unlock()
		r := &sliceReader{b: buf[3:n]}
		host, port, err := readAddr(r)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		ip, err := a.p.lookup(ctx, host)
		cancel()
		if err != nil {
			continue
		}
		u, err := a.socket(ip.Is4())
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			continue
		}
		u.WriteTo(r.b, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, port)))
	}
}

func (a *association) toClient(u *gonet.UDPConn) {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := u.ReadFrom(buf)
		if err != nil {
			return
		}
		src, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		a.mu.Lock()
		client := a.client
		a.mu.Unlock()
		dgram := appendAddr([]byte{0, 0, 0}, src.AddrPort())
		a.relay.WriteToUDPAddrPort(append(dgram, buf[:n]...), client)
	}
}

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
