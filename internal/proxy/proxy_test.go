package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/windows/conf"

	"splitwire/internal/config"
)

// server runs a WireGuard peer at 10.9.0.1 in user space, with an HTTP
// server on port 80, a UDP echo on port 7, and on port 81 a server that
// reads everything and never answers or closes.
func server(t *testing.T, clientPub *conf.Key) (pub *conf.Key, port int) {
	t.Helper()
	key, err := conf.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "server: "))
	t.Cleanup(dev.Close)
	err = dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=10.9.0.2/32\n",
		hex.EncodeToString(key[:]), hex.EncodeToString(clientPub[:])))
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	get, _ := dev.IpcGet()
	for _, l := range strings.Split(get, "\n") {
		if v, ok := strings.CutPrefix(l, "listen_port="); ok {
			fmt.Sscan(v, &port)
		}
	}

	ln, err := tnet.ListenTCPAddrPort(netip.MustParseAddrPort("10.9.0.1:80"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s", r.URL.Path)
	}))
	silent, err := tnet.ListenTCPAddrPort(netip.MustParseAddrPort("10.9.0.1:81"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { silent.Close() })
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
			go io.Copy(io.Discard, c)
		}
	}()
	echo, err := tnet.ListenUDPAddrPort(netip.MustParseAddrPort("10.9.0.1:7"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(buf[:n], from)
		}
	}()
	return key.Public(), port
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func start(t *testing.T) *Proxy {
	key, err := conf.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	srvPub, srvPort := server(t, key.Public())
	text := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.9.0.2/32

[Peer]
PublicKey = %s
Endpoint = 127.0.0.1:%d
AllowedIPs = 10.9.0.0/24

[SplitWire]
Proxy = %d
`, key.String(), srvPub.String(), srvPort, freePort(t))
	c, err := config.Parse(text, "test")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Start(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestProxy(t *testing.T) {
	p := start(t)
	addr := p.Listen().String()

	t.Run("socks5 connect", func(t *testing.T) {
		d, err := xproxy.SOCKS5("tcp", addr, nil, xproxy.Direct)
		if err != nil {
			t.Fatal(err)
		}
		client := &http.Client{Transport: &http.Transport{Dial: d.Dial}, Timeout: 10 * time.Second}
		resp, err := client.Get("http://10.9.0.1/socks")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "hello /socks" {
			t.Fatalf("body %q", body)
		}
	})

	t.Run("http forward", func(t *testing.T) {
		u, _ := url.Parse("http://" + addr)
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 10 * time.Second}
		resp, err := client.Get("http://10.9.0.1/plain")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "hello /plain" {
			t.Fatalf("body %q", body)
		}
	})

	t.Run("http connect", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(c, "CONNECT 10.9.0.1:80 HTTP/1.1\r\nHost: 10.9.0.1:80\r\n\r\n")
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("CONNECT: %v %v", resp, err)
		}
		fmt.Fprintf(c, "GET /tunnel HTTP/1.1\r\nHost: 10.9.0.1\r\nConnection: close\r\n\r\n")
		resp, err = http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "hello /tunnel" {
			t.Fatalf("body %q", body)
		}
	})

	t.Run("socks5 udp", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		c.Write([]byte{5, 1, 0})
		var greet [2]byte
		if _, err := io.ReadFull(c, greet[:]); err != nil || greet[1] != 0 {
			t.Fatalf("greeting %v %v", greet, err)
		}
		c.Write([]byte{5, cmdUDPAssociate, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
		var rep [3]byte
		if _, err := io.ReadFull(c, rep[:]); err != nil || rep[1] != repSuccess {
			t.Fatalf("reply %v %v", rep, err)
		}
		host, port, err := readAddr(c)
		if err != nil {
			t.Fatal(err)
		}
		u, err := net.Dial("udp", net.JoinHostPort(host, fmt.Sprint(port)))
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		u.SetDeadline(time.Now().Add(10 * time.Second))
		dgram := appendAddr([]byte{0, 0, 0}, netip.MustParseAddrPort("10.9.0.1:7"))
		u.Write(append(dgram, "ping"...))
		buf := make([]byte, 2048)
		n, err := u.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf[:n], append(dgram, "ping"...)) {
			t.Fatalf("echo %x", buf[:n])
		}
	})

	peers, err := p.Peers()
	if err != nil || len(peers) != 1 || peers[0].LastHandshake.IsZero() || peers[0].RxBytes == 0 {
		t.Fatalf("peers %+v %v", peers, err)
	}
}

// connectSOCKS opens a SOCKS5 CONNECT through the proxy to target.
func connectSOCKS(t *testing.T, p *Proxy, target string) *net.TCPConn {
	t.Helper()
	d, err := xproxy.SOCKS5("tcp", p.Listen().String(), nil, xproxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	c, err := d.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*net.TCPConn)
}

// waitIdle fails the test unless the proxy holds no connections within d.
func waitIdle(t *testing.T, p *Proxy, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		p.mu.Lock()
		n := len(p.conns)
		p.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy still holds %d connections after %s", n, d)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A client that goes away ends its connection even when the target never
// answers or closes.
func TestClientGoneSilentTarget(t *testing.T) {
	defer func(d time.Duration) { halfCloseIdle = d }(halfCloseIdle)
	halfCloseIdle = 300 * time.Millisecond
	p := start(t)

	t.Run("reset", func(t *testing.T) {
		c := connectSOCKS(t, p, "10.9.0.1:81")
		c.Write([]byte("request"))
		c.SetLinger(0)
		c.Close()
		waitIdle(t, p, 5*time.Second)
	})
	t.Run("close", func(t *testing.T) {
		c := connectSOCKS(t, p, "10.9.0.1:81")
		c.Write([]byte("request"))
		c.Close()
		waitIdle(t, p, 5*time.Second)
	})
	t.Run("half close", func(t *testing.T) {
		c := connectSOCKS(t, p, "10.9.0.1:81")
		defer c.Close()
		c.Write([]byte("request"))
		c.CloseWrite()
		waitIdle(t, p, 5*time.Second)
	})
	t.Run("http request", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", p.Listen().String(), 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "GET http://10.9.0.1:81/ HTTP/1.1\r\nHost: 10.9.0.1:81\r\n\r\n")
		c.Close()
		waitIdle(t, p, 5*time.Second)
	})
}

// A half close passes through, and the answer that follows it still
// reaches the client.
func TestHalfCloseAnswer(t *testing.T) {
	p := start(t)
	c := connectSOCKS(t, p, "10.9.0.1:80")
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "GET /half HTTP/1.1\r\nHost: 10.9.0.1\r\n\r\n")
	c.CloseWrite()
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello /half" {
		t.Fatalf("body %q", body)
	}
}

func TestAddrRoundTrip(t *testing.T) {
	for _, s := range []string{"10.1.2.3:80", "[2001:db8::1]:443"} {
		ap := netip.MustParseAddrPort(s)
		host, port, err := readAddr(bytes.NewReader(appendAddr(nil, ap)))
		if err != nil || host != ap.Addr().String() || port != ap.Port() {
			t.Fatalf("%s became %s %d %v", s, host, port, err)
		}
	}
	b := []byte{atypDomain, 11}
	b = binary.BigEndian.AppendUint16(append(b, "example.com"...), 8080)
	host, port, err := readAddr(bytes.NewReader(b))
	if err != nil || host != "example.com" || port != 8080 {
		t.Fatalf("domain became %s %d %v", host, port, err)
	}
}

// A proxy that cannot start, here on a port in use, reports an error
// instead of failing while it undoes its start.
func TestStartFailure(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	key, err := conf.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.9.0.2/32\n\n[Peer]\nPublicKey = %s\n"+
		"Endpoint = 127.0.0.1:9\nAllowedIPs = 0.0.0.0/0\n\n[SplitWire]\nProxy = %s\n",
		key, key.Public(), taken.Addr())
	c, err := config.Parse(text, "busy")
	if err != nil {
		t.Fatal(err)
	}
	if p, err := Start(c); err == nil {
		p.Close()
		t.Fatal("started on a port in use")
	}
}
