package userconf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetKey(t *testing.T) {
	dir := t.TempDir()
	cases := []struct{ in, want string }{
		{
			"[Interface]\r\nAddress = 10.0.0.2/32\r\n",
			"[Interface]\r\nAddress = 10.0.0.2/32\r\n\r\n[SplitWire]\r\nProxy = 1080\r\n",
		},
		{
			"[Interface]\n\n# [SplitWire]\n# Mode = include\n",
			"[Interface]\n\n# [SplitWire]\n# Mode = include\n\n[SplitWire]\nProxy = 1080\n",
		},
		{
			"[Interface]\n\n[splitwire]  # options\nMode = full\n",
			"[Interface]\n\n[splitwire]  # options\nMode = full\nProxy = 1080\n",
		},
		{
			"[Interface]\n\n[SplitWire]\nMode = full\n\n[SplitWire]\n  proxy = 2000 # old\n",
			"[Interface]\n\n[SplitWire]\nMode = full\n\n[SplitWire]\nProxy = 1080\n",
		},
		{
			"[Interface]\n# Proxy = 9\n\n# [SplitWire]\n",
			"[Interface]\n# Proxy = 9\n\n# [SplitWire]\n\n[SplitWire]\nProxy = 1080\n",
		},
	}
	for i, c := range cases {
		path := filepath.Join(dir, "t.conf")
		if err := os.WriteFile(path, []byte(c.in), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := setKey(path, "Proxy", "1080"); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(path)
		if string(got) != c.want {
			t.Errorf("case %d:\n%q\nwant\n%q", i, got, c.want)
		}
	}
}
