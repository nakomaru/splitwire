package logx

import (
	"fmt"
	"os"
	"path/filepath"
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

func TestFileMovesAside(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	f, err := OpenFile(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"aaaa\n", "bbbb\n", "cccc\n", "dddd\n"} {
		if _, err := f.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	cur, _ := os.ReadFile(path)
	old, _ := os.ReadFile(path + ".1")
	if string(cur) != "cccc\ndddd\n" || string(old) != "aaaa\nbbbb\n" {
		t.Fatalf("file %q, moved aside %q", cur, old)
	}
	if _, err := f.Write([]byte("late\n")); err == nil {
		t.Fatal("wrote after Close")
	}
}

// A file another process holds keeps growing, and moves aside once free.
func TestFileHeldElsewhere(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	f, err := OpenFile(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write([]byte("aaaa\nbbbb\n"))
	holder, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("cccc\n"))
	holder.Close()
	if cur, _ := os.ReadFile(path); string(cur) != "aaaa\nbbbb\ncccc\n" {
		t.Fatalf("held file %q", cur)
	}
	f.Write([]byte("dddd\neeee\n"))
	cur, _ := os.ReadFile(path)
	old, _ := os.ReadFile(path + ".1")
	if string(cur) != "dddd\neeee\n" || string(old) != "aaaa\nbbbb\ncccc\n" {
		t.Fatalf("file %q, moved aside %q", cur, old)
	}
}
