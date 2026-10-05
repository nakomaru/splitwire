package warp

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/windows/conf"

	"splitwire/internal/config"
)

func TestConfigParses(t *testing.T) {
	key, err := conf.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	d := &Device{
		ID: "device-id", Token: "secret", PrivateKey: key,
		PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		Endpoint:      Endpoint, IPv4: "172.16.0.2", IPv6: "2606:4700:110:8e9c::1", AccountType: "free",
	}
	text := d.Config()
	c, err := config.Parse(text, "WARP")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.WG.Interface.Addresses) != 2 || !c.HasDefaultRoute() || c.Mode != config.ModeFull {
		t.Fatalf("parsed %+v", c.WG.Interface)
	}
	if !strings.Contains(text, "WarpToken = secret") || !strings.Contains(text, "[Splitwire]") {
		t.Fatal("token or example section missing")
	}
}
