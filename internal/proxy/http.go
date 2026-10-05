package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// hopHeaders are meaningful only between the client and the proxy.
var hopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailer", "Upgrade",
}

// serveHTTP serves one HTTP proxy request: a CONNECT tunnel, or a plain request
// forwarded with an absolute URL. Each plain request closes the connection
// after its response.
func (p *Proxy) serveHTTP(c net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		target, err := p.dial(ctx, withPort(req.Host, "443"))
		cancel()
		if err != nil {
			writeStatus(c, http.StatusBadGateway)
			return
		}
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			target.Close()
			return
		}
		c.SetDeadline(time.Time{})
		p.pipe(c, br, target)
		return
	}
	if !req.URL.IsAbs() || req.URL.Scheme != "http" {
		writeStatus(c, http.StatusBadRequest)
		return
	}
	c.SetDeadline(time.Time{})
	for _, h := range hopHeaders {
		req.Header.Del(h)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	target, err := p.dial(ctx, withPort(req.URL.Host, "80"))
	cancel()
	if err != nil {
		writeStatus(c, http.StatusBadGateway)
		return
	}
	if !p.track(target) {
		return
	}
	defer p.untrack(target)
	req.Close = true
	if err := req.Write(target); err != nil {
		writeStatus(c, http.StatusBadGateway)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(target), req)
	if err != nil {
		writeStatus(c, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	resp.Close = true
	resp.Write(c)
}

func withPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port)
}

func writeStatus(c net.Conn, code int) {
	text := http.StatusText(code)
	c.Write([]byte("HTTP/1.1 " + strconv.Itoa(code) + " " + text + "\r\nContent-Type: text/plain; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(text)+1) + "\r\nConnection: close\r\n\r\n" + text + "\n"))
}
