// Package warp registers devices with Cloudflare WARP and writes them as
// WireGuard tunnels. It speaks the registration API of the WARP mobile app,
// which Cloudflare does not document; wgcf and similar tools use the same
// requests.
package warp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"

	"splitwire/internal/config"
)

const (
	apiBase       = "https://api.cloudflareclient.com/v0a1922"
	userAgent     = "okhttp/3.12.1"
	clientVersion = "a-6.3-1922"
	// Endpoint is the WARP WireGuard endpoint the official clients use.
	Endpoint = "engage.cloudflareclient.com:2408"
)

// Device is a registered WARP device.
type Device struct {
	ID, Token     string
	PrivateKey    *conf.Key
	PeerPublicKey string
	Endpoint      string
	IPv4, IPv6    string
	AccountType   string
}

type regResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		AccountType string `json:"account_type"`
	} `json:"account"`
	Config struct {
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func call(ctx context.Context, method, path, token string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiBase+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("CF-Client-Version", clientVersion)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("Cloudflare answered %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

// Register creates a free WARP device for a new key pair and turns WARP on
// for it.
func Register(ctx context.Context) (*Device, error) {
	key, err := conf.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	var reg regResponse
	err = call(ctx, http.MethodPost, "/reg", "", map[string]any{
		"install_id": "",
		"fcm_token":  "",
		"tos":        time.Now().UTC().Format(time.RFC3339),
		"key":        key.Public().String(),
		"type":       "Android",
		"model":      "PC",
		"locale":     "en_US",
	}, &reg)
	if err != nil {
		return nil, fmt.Errorf("register with WARP: %w", err)
	}
	if reg.ID == "" || reg.Token == "" || len(reg.Config.Peers) == 0 || reg.Config.Interface.Addresses.V4 == "" {
		return nil, fmt.Errorf("register with WARP: the answer lacks the device or its configuration")
	}
	d := &Device{
		ID:            reg.ID,
		Token:         reg.Token,
		PrivateKey:    key,
		PeerPublicKey: reg.Config.Peers[0].PublicKey,
		Endpoint:      reg.Config.Peers[0].Endpoint.Host,
		IPv4:          reg.Config.Interface.Addresses.V4,
		IPv6:          reg.Config.Interface.Addresses.V6,
		AccountType:   reg.Account.AccountType,
	}
	if d.Endpoint == "" {
		d.Endpoint = Endpoint
	}
	if err := call(ctx, http.MethodPatch, "/reg/"+d.ID, d.Token, map[string]any{"warp_enabled": true}, nil); err != nil {
		Delete(ctx, d.ID, d.Token)
		return nil, fmt.Errorf("turn WARP on: %w", err)
	}
	return d, nil
}

// Delete removes a registered device from Cloudflare.
func Delete(ctx context.Context, id, token string) error {
	return call(ctx, http.MethodDelete, "/reg/"+id, token, nil, nil)
}

// Config is the device as a WireGuard configuration that routes everything
// through WARP. Its comments record the device ID and token, which Delete
// needs.
func (d *Device) Config() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Cloudflare WARP device %s (%s account), created by splitwire %s.\n",
		d.ID, d.AccountType, time.Now().Format("2006-01-02 15:04"))
	fmt.Fprintf(&b, "# WarpToken = %s\n\n", d.Token)
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", d.PrivateKey.String())
	addrs := d.IPv4 + "/32"
	if d.IPv6 != "" {
		addrs += ", " + d.IPv6 + "/128"
	}
	fmt.Fprintf(&b, "Address = %s\n", addrs)
	b.WriteString("DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001\n")
	b.WriteString("MTU = 1280\n\n")
	b.WriteString("[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", d.PeerPublicKey)
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n\n", d.Endpoint)
	b.WriteString(config.ExampleSection)
	return b.String()
}
