package scan

import (
	"bufio"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// This file handles the artifacts that are not name lists: URL lists from the HTTP
// and crawl phases, and host:port lines from the port scan. They cannot go through
// Set, which normalises everything to a bare hostname — that is the right behaviour
// for master_dns.txt and the wrong behaviour for a list of things to attack.

// newLineScanner returns a line scanner whose buffer is large enough for the data
// this tool actually meets. The 64 KiB default silently truncates long archived URLs
// mid-line, and a truncated URL yields a hostname that was never real.
func newLineScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	return sc
}

// LoadLines reads a file into a slice, dropping blanks and stripping the trailing
// carriage returns that appear whenever a tool was built for Windows or a wordlist
// was edited there. A missing file is an empty slice, matching LoadSet.
func LoadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := newLineScanner(f)
	for sc.Scan() {
		if s := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r")); s != "" {
			out = append(out, s)
		}
	}
	return out, sc.Err()
}

// WriteLines writes a sorted, deduplicated slice atomically, by the same
// temp-then-rename route Set.WriteFile uses and for the same reason: an artifact is
// either the previous run's or this one's, never half of each.
func WriteLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(lines))
	uniq := make([]string, 0, len(lines))
	for _, l := range lines {
		if _, dup := seen[l]; dup {
			continue
		}
		seen[l] = struct{}{}
		uniq = append(uniq, l)
	}
	sort.Strings(uniq)

	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	w := bufio.NewWriter(tmp)
	for _, l := range uniq {
		if _, err := w.WriteString(l + "\n"); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// KeepHTTP filters a slice down to http and https URLs. Crawlers emit mailto:,
// javascript: and tel: links, and handing those to httpx or nuclei wastes a slot per
// entry and clutters the log with parse errors.
func KeepHTTP(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
			out = append(out, l)
		}
	}
	return out
}

// HostOf extracts the hostname from a URL, discarding scheme, userinfo, port, path,
// query and fragment.
//
// net/url does this correctly, including for the IPv6 literals and the embedded
// credentials that turn up constantly in archived data. The shell version used
// `awk -F/ '{print $3}'`, which returns `user:pass@host:8443` for those inputs and
// puts that string into the report as a hostname.
func HostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// HostsOf pulls the in-scope hostnames out of a URL list. This is what folds crawl
// output back into the DNS results: names that appear only in a JavaScript bundle or
// a CSP header are never seen by any amount of DNS brute forcing.
func HostsOf(urls []string, target string) *Set {
	s := NewSet()
	for _, u := range urls {
		if h := HostOf(u); h != "" {
			s.Add(h)
		}
	}
	return s.InScope(target)
}

// HostPort splits a naabu `host:port` line. Anything without a port is returned with
// port "" so the caller can decide, rather than being silently dropped.
func HostPort(line string) (string, string) {
	i := strings.LastIndex(line, ":")
	if i < 0 {
		return line, ""
	}
	return line[:i], line[i+1:]
}

// URLsFromJSONL pulls the `url` field out of httpx JSONL output.
//
// The shell fell back to sed when jq was absent, and a narrow sed still matches
// `"url":` inside a page title. Here the field is read from a parsed object, so a
// title containing JSON cannot contribute a URL. Lines that do not parse are skipped
// rather than failing the phase: httpx occasionally interleaves a warning into
// stdout, and one bad line is not a reason to discard a completed probe.
func URLsFromJSONL(path string) ([]string, error) {
	lines, err := LoadLines(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		var rec struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			continue
		}
		if rec.URL != "" {
			out = append(out, rec.URL)
		}
	}
	return out, nil
}
