// Package scan holds the pipeline: name sets, phase state, command execution and
// the phase graph itself.
//
// The set operations here are the part of the rewrite that removes the largest
// class of portability bug. The shell pipeline expressed every merge and
// difference as `sort -u`, `comm -23` and `comm -12`, which are correct only when
// every participant agrees on collation — so a master list written on a glibc host
// under en_US and re-read on macOS under C would silently disagree about
// ordering, and `comm` would report differences that do not exist. A map plus one
// deterministic byte-wise sort at write time has no such failure mode.
package scan

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
)

// Set is a deduplicated collection of DNS names.
type Set struct {
	m map[string]struct{}
}

func NewSet() *Set { return &Set{m: make(map[string]struct{})} }

// Add normalises and stores a name, reporting whether it was new. Empty or
// unusable input is dropped rather than stored, so callers do not have to filter
// before adding.
func (s *Set) Add(raw string) bool {
	n := Normalise(raw)
	if n == "" {
		return false
	}
	if _, seen := s.m[n]; seen {
		return false
	}
	s.m[n] = struct{}{}
	return true
}

func (s *Set) AddAll(names []string) int {
	added := 0
	for _, n := range names {
		if s.Add(n) {
			added++
		}
	}
	return added
}

// Merge folds another set in and returns how many names were new.
func (s *Set) Merge(o *Set) int {
	added := 0
	if o == nil {
		return 0
	}
	for k := range o.m {
		if _, seen := s.m[k]; !seen {
			s.m[k] = struct{}{}
			added++
		}
	}
	return added
}

func (s *Set) Has(raw string) bool {
	_, ok := s.m[Normalise(raw)]
	return ok
}

func (s *Set) Len() int { return len(s.m) }

// Sorted returns the names in byte order. Byte order rather than locale order on
// purpose: the result is written to disk and compared across machines, so it has
// to be reproducible independently of the environment.
func (s *Set) Sorted() []string {
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Minus returns the names in s that are not in o.
func (s *Set) Minus(o *Set) *Set {
	r := NewSet()
	for k := range s.m {
		if o == nil {
			r.m[k] = struct{}{}
			continue
		}
		if _, seen := o.m[k]; !seen {
			r.m[k] = struct{}{}
		}
	}
	return r
}

// Intersect returns the names present in both sets.
func (s *Set) Intersect(o *Set) *Set {
	r := NewSet()
	if o == nil {
		return r
	}
	for k := range s.m {
		if _, seen := o.m[k]; seen {
			r.m[k] = struct{}{}
		}
	}
	return r
}

// InScope keeps only names at or under target.
func (s *Set) InScope(target string) *Set {
	r := NewSet()
	for k := range s.m {
		if InScope(k, target) {
			r.m[k] = struct{}{}
		}
	}
	return r
}

// LoadSet reads a name-per-line file. A missing file is an empty set, not an
// error: every phase artifact is optional on a resumed run, and treating absence
// as failure was why the shell version needed a `[ -s ... ]` guard at every call
// site.
func LoadSet(path string) (*Set, error) {
	s := NewSet()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	// Crawl output can carry very long URLs; the default 64 KiB token limit
	// truncates them mid-line and produces corrupt hostnames.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		s.Add(sc.Text())
	}
	return s, sc.Err()
}

// WriteFile writes the sorted set atomically. The temporary file is created in the
// destination directory so the rename cannot cross a filesystem boundary, and a
// crash mid-write leaves the previous artifact intact rather than a half-written
// one that the next resume would treat as complete.
func (s *Set) WriteFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	w := bufio.NewWriter(tmp)
	for _, n := range s.Sorted() {
		if _, err := w.WriteString(n + "\n"); err != nil {
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
