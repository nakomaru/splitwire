package config

import "strings"

// Edits of configuration text keep its comments, blank lines, line endings
// and the order of its lines. A setting the text lacks goes after the last
// setting of its first [Splitwire] section, or into a new section at the
// end.

// lineSplit splits text into lines and reports its line ending.
func lineSplit(text string) ([]string, string) {
	nl := "\n"
	if strings.Contains(text, "\r\n") {
		nl = "\r\n"
	}
	return strings.Split(text, nl), nl
}

// sectionLine classifies a line: a section header, or a setting with its
// key in lowercase.
func sectionLine(line string) (header, key string) {
	code, _, _ := strings.Cut(line, "#")
	stripped := strings.TrimSpace(code)
	if strings.HasPrefix(stripped, "[") && !strings.Contains(stripped, "=") {
		return stripped, ""
	}
	if k, _, ok := strings.Cut(stripped, "="); ok {
		return "", strings.ToLower(strings.TrimSpace(k))
	}
	return "", ""
}

// settingLines finds the [Splitwire] settings: the line indexes of each
// key, the first section's header and the last setting in that section.
// first is -1 without a section.
func settingLines(lines []string) (keys map[string][]int, first, last int) {
	keys = make(map[string][]int)
	first, last = -1, -1
	in, inFirst := false, false
	for i, line := range lines {
		header, key := sectionLine(line)
		if header != "" {
			in = strings.EqualFold(header, sectionName)
			inFirst = in && first < 0
			if inFirst {
				first, last = i, i
			}
			continue
		}
		if in && key != "" {
			keys[key] = append(keys[key], i)
			if inFirst {
				last = i
			}
		}
	}
	return keys, first, last
}

// insertAt puts entries before index i, or appends them to a new section
// when i is -1.
func insertAt(lines []string, i int, entries []string) []string {
	if i < 0 {
		for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
			lines = lines[:len(lines)-1]
		}
		lines = append(lines, "", "[Splitwire]")
		return append(append(lines, entries...), "")
	}
	out := append([]string{}, lines[:i]...)
	out = append(out, entries...)
	return append(out, lines[i:]...)
}

// without removes the lines at the sorted indexes.
func without(lines []string, drop []int) []string {
	out := lines[:0:0]
	for i, line := range lines {
		if len(drop) > 0 && drop[0] == i {
			drop = drop[1:]
			continue
		}
		out = append(out, line)
	}
	return out
}

// SetValue sets key = val in the [Splitwire] section of text: it replaces
// the key's line and drops any repeats of it. A key the text lacks is added
// unless val is its default, given by isDefault.
func SetValue(text, key, val string, isDefault bool) string {
	lines, nl := lineSplit(text)
	keys, first, last := settingLines(lines)
	entry := key + " = " + val
	if at := keys[strings.ToLower(key)]; len(at) > 0 {
		lines[at[0]] = entry
		return strings.Join(without(lines, at[1:]), nl)
	}
	if isDefault {
		return text
	}
	if first < 0 {
		return strings.Join(insertAt(lines, -1, []string{entry}), nl)
	}
	return strings.Join(insertAt(lines, last+1, []string{entry}), nl)
}

// SetApps replaces the App entries of text with apps, in the place of the
// first one, or after the Mode setting when the text has none.
func SetApps(text string, apps []string) string {
	lines, nl := lineSplit(text)
	keys, first, last := settingLines(lines)
	entries := make([]string, len(apps))
	for i, a := range apps {
		entries[i] = "App = " + a
	}
	if at := keys["app"]; len(at) > 0 {
		lines = without(lines, at)
		return strings.Join(insertAt(lines, at[0], entries), nl)
	}
	if len(entries) == 0 {
		return text
	}
	switch {
	case first < 0:
		lines = insertAt(lines, -1, entries)
	case len(keys["mode"]) > 0:
		lines = insertAt(lines, keys["mode"][0]+1, entries)
	default:
		lines = insertAt(lines, last+1, entries)
	}
	return strings.Join(lines, nl)
}
