package tray

import (
	"strings"
	"unicode/utf16"
)

// Syntax styles of a tunnel's text.
const (
	synSection = iota
	synKey
	synString
	synNumber
	synKeyword
	synComment
	synError
)

// keywords are the values that name a choice.
var keywords = map[string]bool{
	"on": true, "off": true, "true": true, "false": true, "yes": true, "no": true,
	"auto": true, "full": true, "include": true, "exclude": true, "vpn": true,
}

// confSpans finds the styled runs of a WireGuard configuration, in UTF-16
// units, with \n line breaks counting one unit. errLine, from 1, marks a
// line with a problem.
func confSpans(text string, errLine int) []span {
	var out []span
	pos := 0 // UTF-16 offset of the line's start
	for i, line := range strings.Split(text, "\n") {
		width := func(s string) int { return len(utf16.Encode([]rune(s))) }
		at := func(byteOff int) int { return pos + width(line[:byteOff]) }
		add := func(from, to, style int) {
			if to > from {
				out = append(out, span{at(from), at(to), style})
			}
		}
		code := line
		if c := strings.IndexByte(line, '#'); c >= 0 {
			code = line[:c]
			add(c, len(line), synComment)
		}
		lead := len(code) - len(strings.TrimLeft(code, " \t"))
		end := len(strings.TrimRight(code, " \t"))
		switch {
		case i+1 == errLine && end > lead:
			add(lead, end, synError)
		case end <= lead:
		case code[lead] == '[':
			add(lead, end, synSection)
		case strings.IndexByte(code, '=') >= 0:
			eq := strings.IndexByte(code, '=')
			add(lead, len(strings.TrimRight(code[:eq], " \t")), synKey)
			// Each comma-separated item of the value.
			from := eq + 1
			for from <= end {
				to := strings.IndexByte(code[from:end], ',')
				if to < 0 {
					to = end
				} else {
					to += from
				}
				item := code[from:to]
				s := from + len(item) - len(strings.TrimLeft(item, " \t"))
				e := from + len(strings.TrimRight(item, " \t"))
				if e > s {
					add(s, e, valueStyle(code[s:e]))
				}
				from = to + 1
			}
		}
		pos += width(line) + 1
	}
	return out
}

// valueStyle styles one item of a value: a choice, an address or number,
// or text.
func valueStyle(v string) int {
	if keywords[strings.ToLower(v)] {
		return synKeyword
	}
	digit := false
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'a' && r <= 'f', r >= 'A' && r <= 'F', strings.ContainsRune(".:/[]", r):
		default:
			return synString
		}
	}
	if digit {
		return synNumber
	}
	return synString
}

// syntaxStyles are the colors of the syntax styles, after the editors of
// Visual Studio Code.
func syntaxStyles(col colors) (richStyle, map[int]richStyle) {
	base := richStyle{color: col.text}
	if highContrast() {
		return base, map[int]richStyle{synSection: {color: col.text, bold: true}, synError: {color: col.text, squiggled: true}}
	}
	if col.dark {
		return base, map[int]richStyle{
			synSection: {color: rgb(0x56, 0x9c, 0xd6), bold: true},
			synKey:     {color: rgb(0x9c, 0xdc, 0xfe)},
			synString:  {color: rgb(0xce, 0x91, 0x78)},
			synNumber:  {color: rgb(0xb5, 0xce, 0xa8)},
			synKeyword: {color: rgb(0xc5, 0x86, 0xc0)},
			synComment: {color: rgb(0x6a, 0x99, 0x55), italic: true},
			synError:   {color: col.err, squiggled: true},
		}
	}
	return base, map[int]richStyle{
		synSection: {color: rgb(0x00, 0x00, 0xff), bold: true},
		synKey:     {color: rgb(0x00, 0x10, 0x80)},
		synString:  {color: rgb(0xa3, 0x15, 0x15)},
		synNumber:  {color: rgb(0x09, 0x86, 0x58)},
		synKeyword: {color: rgb(0xaf, 0x00, 0xdb)},
		synComment: {color: rgb(0x00, 0x80, 0x00), italic: true},
		synError:   {color: col.err, squiggled: true},
	}
}
