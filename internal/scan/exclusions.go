package scan

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Exclusions are operator supplied collection filters, not ownership decisions.
// A wildcard matches descendants only; its suffix apex remains eligible.
func ReadExclusions(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	lines, err := LoadLines(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for i, line := range lines {
		line = strings.ToLower(strings.TrimSpace(strings.SplitN(line, "#", 2)[0]))
		if line == "" {
			continue
		}
		name := strings.TrimPrefix(line, "*.")
		if !validName(name) || strings.Contains(name, "*") {
			return nil, fmt.Errorf("%s:%d: expected a hostname or *.suffix", path, i+1)
		}
		set[line] = true
	}
	out := make([]string, 0, len(set))
	for pattern := range set {
		out = append(out, pattern)
	}
	// ASCII patterns have the same ordering as LC_ALL=C in the shell.
	sort.Strings(out)
	return out, nil
}

func (p *Pipeline) excluded(name string) bool {
	for _, pattern := range p.exclusions {
		if strings.HasPrefix(pattern, "*.") {
			if strings.HasSuffix(name, pattern[1:]) {
				return true
			}
		} else if name == pattern {
			return true
		}
	}
	return false
}

func (p *Pipeline) allowed(s *Set) *Set {
	out := NewSet()
	for n := range s.m {
		if InScope(n, p.opt.Target) && !p.excluded(n) {
			out.m[n] = struct{}{}
		}
	}
	return out
}

func (p *Pipeline) collectedURLs(lines []string) []string {
	var out []string
	for _, line := range KeepHTTP(lines) {
		if !p.excluded(Normalise(line)) {
			out = append(out, line)
		}
	}
	return out
}

// Persist normalized patterns so continuation cannot silently change selection.
func (p *Pipeline) bindExclusions() error {
	path := p.L.Path("collection-exclusions.txt")
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	want := strings.Join(p.exclusions, "\n")
	if want != "" {
		want += "\n"
	}
	if p.L.Resumed && string(old) != want {
		return fmt.Errorf("collection exclusions differ from this run; use the same exclusion file or --fresh")
	}
	return os.WriteFile(path, []byte(want), 0o644)
}
