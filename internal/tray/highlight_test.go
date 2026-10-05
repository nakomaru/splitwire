package tray

import (
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"splitwire/internal/config"
)

// spanText is the text of a span of text, whose offsets count UTF-16 units.
func spanText(text string, sp span) string {
	u := utf16.Encode([]rune(text))
	if sp.start < 0 || sp.end > len(u) || sp.start >= sp.end {
		return ""
	}
	return string(utf16.Decode(u[sp.start:sp.end]))
}

func TestConfSpans(t *testing.T) {
	smile := string(rune(0x1F600)) // two UTF-16 units
	text := strings.Join([]string{
		"[Interface]",
		"PrivateKey = abc+/= # secret",
		"Address = 10.0.0.2/32, fd00::2/128",
		"# " + smile + " note",
		"[SplitWire]",
		"Mode = include",
		`App = C:\Games\game.exe`,
		"Nonsense",
	}, "\n")
	want := map[string]int{
		"[Interface]":          synSection,
		"PrivateKey":           synKey,
		"abc+/=":               synString,
		"# secret":             synComment,
		"Address":              synKey,
		"10.0.0.2/32":          synNumber,
		"fd00::2/128":          synNumber,
		"# " + smile + " note": synComment,
		"[SplitWire]":          synSection,
		"Mode":                 synKey,
		"include":              synKeyword,
		"App":                  synKey,
		`C:\Games\game.exe`:    synString,
	}
	got := map[string]int{}
	for _, sp := range confSpans(text, 0) {
		s := spanText(text, sp)
		if s == "" {
			t.Fatalf("span %+v is outside the text", sp)
		}
		got[s] = sp.style
	}
	for s, style := range want {
		if g, ok := got[s]; !ok || g != style {
			t.Errorf("%q: style %d (found %v), want %d", s, g, ok, style)
		}
	}
	if len(got) != len(want) {
		t.Errorf("spans %v, want %d of them", got, len(want))
	}

	text = "[Interface]\nListenPort = nope # why\n"
	var styled []string
	for _, sp := range confSpans(text, 2) {
		styled = append(styled, spanText(text, sp)+"/"+string(rune('0'+sp.style)))
	}
	if g, w := strings.Join(styled, " | "), "[Interface]/0 | # why/5 | ListenPort = nope/6"; g != w {
		t.Errorf("error line spans %q, want %q", g, w)
	}
}

func TestColorizeOutsideUndo(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	f := &form{}
	newForm(f, "test", 0, wsOverlappedWindow, 400, 300)
	defer procDestroyWindow.Call(f.hwnd)
	c := f.addRich(&control{font: fontMono}, esMultiline)
	if c.doc == nil {
		t.Fatal("no text object model")
	}
	f.setText(c, "[Interface]\r\nMTU = 1420\r\n")
	before, _, _ := procSendMessageW.Call(c.hwnd, emCanUndo, 0, 0)
	base, styles := syntaxStyles(f.col)
	f.colorize(c, base, confSpans("[Interface]\nMTU = 1420\n", 0), styles)
	if after, _, _ := procSendMessageW.Call(c.hwnd, emCanUndo, 0, 0); after != before {
		t.Errorf("coloring changed the undo history: can undo %d, then %d", before, after)
	}
	// "MTU" starts after "[Interface]" and its line break.
	r := charRange{12, 15}
	procSendMessageW.Call(c.hwnd, emExSetSel, 0, uintptr(unsafe.Pointer(&r)))
	cf := newCharFormat(cfmColor)
	procSendMessageW.Call(c.hwnd, emGetCharFormat, scfSelection, uintptr(unsafe.Pointer(&cf)))
	if cf.color != styles[synKey].color {
		t.Errorf("MTU color %06x, want %06x", cf.color, styles[synKey].color)
	}
	if got := normalize(windowText(c.hwnd)); got != "[Interface]\nMTU = 1420\n" {
		t.Errorf("text %q", got)
	}
}

func TestErrorLine(t *testing.T) {
	head := "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n"
	for _, c := range []struct {
		text string
		line int
		msg  string
	}{
		{head + "MTU = nope\n", 3, `"nope" is not a number`},
		{head + "Address = 10.0.0.300/32\n", 3, ""},
		{head + "[SplitWire]\nMode = sideways\n", 4, ""},
	} {
		_, err := config.Parse(c.text, "test")
		if err == nil {
			t.Fatalf("%q parsed", c.text)
		}
		line, msg := errorLine(c.text, err)
		if line != c.line || c.msg != "" && msg != c.msg || strings.HasPrefix(msg, "line ") {
			t.Errorf("%q: line %d, %q; want line %d, %q", err, line, msg, c.line, c.msg)
		}
	}
}

func TestTips(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	useManifest(t)
	f := &form{}
	newForm(f, "test", 0, wsOverlappedWindow, 400, 300)
	defer procDestroyWindow.Call(f.hwnd)
	check := f.add(&control{kind: kindCheck, text: "Kill switch"})
	label := f.add(&control{kind: kindLabel, text: "Allowed IPs"})
	f.setTip(check, "Blocks traffic outside the tunnel.")
	f.setTip(label, "0.0.0.0/0, ::/0")
	f.setTip(label, "10.0.0.0/8")
	const ttmGetToolCount = 0x040D
	if n, _, _ := procSendMessageW.Call(f.tips, ttmGetToolCount, 0, 0); n != 3 {
		t.Errorf("%d tools, want 3: the checkbox's window and place, and the label's place", n)
	}
}
