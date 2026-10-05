package bootstrap

import (
	"strings"
	"testing"
	"unicode/utf16"
)

func multiSZ(pairs ...string) []uint16 {
	return utf16.Encode([]rune(strings.Join(pairs, "\x00") + "\x00\x00"))
}

func TestFilterPending(t *testing.T) {
	data := multiSZ(
		`\??\C:\Windows\Temp\a.tmp`, "",
		`*1\??\C:\Program Files\splitwire\bin\splitwire.exe`, "",
		`\??\C:\Program Files\splitwire`, "",
		`\??\C:\Program Files\splitwire2\x`, "",
		`\??\C:\Program Files\splitwire\moved.txt`, `\??\C:\elsewhere.txt`,
		`*1\??\C:\WRP3DC4.tmp`, "",
	)
	kept, removed := filterPending(data, `C:\Program Files\splitwire`)
	if removed != 2 {
		t.Fatalf("removed %d, want 2", removed)
	}
	want := multiSZ(
		`\??\C:\Windows\Temp\a.tmp`, "",
		`\??\C:\Program Files\splitwire2\x`, "",
		`\??\C:\Program Files\splitwire\moved.txt`, `\??\C:\elsewhere.txt`,
		`*1\??\C:\WRP3DC4.tmp`, "",
	)
	if string(utf16.Decode(kept)) != string(utf16.Decode(want)) {
		t.Fatalf("kept %q\nwant %q", string(utf16.Decode(kept)), string(utf16.Decode(want)))
	}
}
