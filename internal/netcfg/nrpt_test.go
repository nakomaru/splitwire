package netcfg

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestNRPTRuleID(t *testing.T) {
	a, b := nrptRuleID("Office"), nrptRuleID("office")
	if a != b || a == nrptRuleID("home") {
		t.Fatal("rule ID not stable per name")
	}
	g, err := windows.GUIDFromString(a)
	if err != nil {
		t.Fatal(err)
	}
	if g.Data3>>12 != 5 || g.Data4[0]>>6 != 2 {
		t.Fatalf("GUID version/variant bits %s", a)
	}
}
