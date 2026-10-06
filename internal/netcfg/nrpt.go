package netcfg

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Name Resolution Policy Table rules send the lookups of chosen domains to
// chosen DNS servers. SplitWire writes one rule per tunnel with scoped DNS
// to the local policy key, which the DNS client service reads.
const (
	nrptKey   = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	nrptGPKey = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	// nrptComment marks the rules SplitWire wrote.
	nrptComment = "SplitWire"
	// nrptOverrideDNS has the rule's servers answer its domains.
	nrptOverrideDNS = 0x8
)

// nrptRuleID derives a stable rule ID from the tunnel name, so a rule left
// by an unclean exit is replaced on the next start.
func nrptRuleID(tunnel string) string {
	sum := sha256.Sum256([]byte("splitwire dns " + strings.ToLower(tunnel)))
	g := windows.GUID{
		Data1: uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3]),
		Data2: uint16(sum[4])<<8 | uint16(sum[5]),
		Data3: uint16(sum[6])<<8 | uint16(sum[7]),
	}
	copy(g.Data4[:], sum[8:16])
	g.Data3 = g.Data3&0x0fff | 0x5000
	g.Data4[0] = g.Data4[0]&0x3f | 0x80
	return g.String()
}

// SetScopedDNS has the tunnel's servers answer the lookups of domains and
// their subdomains.
func SetScopedDNS(tunnel string, servers []netip.Addr, domains []string) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptKey+`\`+nrptRuleID(tunnel), registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("DNS policy: %w", err)
	}
	defer key.Close()
	names := make([]string, len(domains))
	for i, d := range domains {
		names[i] = "." + strings.Trim(d, ".")
	}
	addrs := make([]string, len(servers))
	for i, s := range servers {
		addrs[i] = s.String()
	}
	for _, set := range []func() error{
		func() error { return key.SetDWordValue("Version", 1) },
		func() error { return key.SetStringsValue("Name", names) },
		func() error { return key.SetStringValue("GenericDNSServers", strings.Join(addrs, ";")) },
		func() error { return key.SetDWordValue("ConfigOptions", nrptOverrideDNS) },
		func() error { return key.SetStringValue("Comment", nrptComment+" "+tunnel) },
	} {
		if err := set(); err != nil {
			return fmt.Errorf("DNS policy: %w", err)
		}
	}
	if policyRulesExist() {
		log.Printf("Warning: Group Policy sets DNS policy rules, which take precedence over %s's DNS for %s",
			tunnel, strings.Join(domains, ", "))
	}
	flushDNS()
	return nil
}

// ClearScopedDNS removes the tunnel's rule.
func ClearScopedDNS(tunnel string) {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptKey+`\`+nrptRuleID(tunnel))
	if err == nil {
		flushDNS()
	} else if !errors.Is(err, registry.ErrNotExist) {
		log.Printf("Warning: remove the DNS policy of %s: %v", tunnel, err)
	}
}

// ClearAllScopedDNS removes every rule SplitWire wrote, and reports how many.
func ClearAllScopedDNS() int {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptKey, registry.READ)
	if err != nil {
		return 0
	}
	ids, _ := key.ReadSubKeyNames(0)
	key.Close()
	removed := 0
	for _, id := range ids {
		rule, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptKey+`\`+id, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		comment, _, _ := rule.GetStringValue("Comment")
		rule.Close()
		if strings.HasPrefix(comment, nrptComment+" ") && registry.DeleteKey(registry.LOCAL_MACHINE, nrptKey+`\`+id) == nil {
			removed++
		}
	}
	if removed > 0 {
		flushDNS()
	}
	return removed
}

// policyRulesExist reports whether Group Policy sets DNS policy rules, which
// replace the local ones.
func policyRulesExist() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptGPKey, registry.READ)
	if err != nil {
		return false
	}
	defer key.Close()
	ids, err := key.ReadSubKeyNames(1)
	return err == nil && len(ids) > 0
}

var procDnsFlushResolverCache = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

// flushDNS empties the DNS client's cache, so new rules apply to names
// looked up before.
func flushDNS() {
	if procDnsFlushResolverCache.Find() == nil {
		procDnsFlushResolverCache.Call()
	}
}
