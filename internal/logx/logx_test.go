package logx

import (
	"fmt"
	"strings"
	"testing"
)

func TestRing(t *testing.T) {
	r := NewRing(3)
	r.Write([]byte("a\n"))
	if got := strings.Join(r.Lines(), ","); got != "a" {
		t.Fatalf("lines %q", got)
	}
	for i := 0; i < 4; i++ {
		fmt.Fprintf(r, "l%d\n", i)
	}
	if got := strings.Join(r.Lines(), ","); got != "l1,l2,l3" {
		t.Fatalf("lines %q", got)
	}
	r.Write([]byte("x\ny\n"))
	if got := strings.Join(r.Lines(), ","); got != "l3,x,y" {
		t.Fatalf("lines %q", got)
	}
}
