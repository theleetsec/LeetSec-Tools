package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetDedupAndOrder(t *testing.T) {
	s := NewSet()
	s.AddAll([]string{"b.example.com", "A.example.com", "a.example.com", "b.example.com."})
	if s.Len() != 2 {
		t.Fatalf("Len() = %d, want 2 (case and trailing dot are the same name)", s.Len())
	}
	got := s.Sorted()
	if got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Errorf("Sorted() = %v, want byte order", got)
	}
}

func TestSetAlgebra(t *testing.T) {
	a, b := NewSet(), NewSet()
	a.AddAll([]string{"one.example.com", "two.example.com", "three.example.com"})
	b.AddAll([]string{"two.example.com", "four.example.com"})

	if n := a.Minus(b).Len(); n != 2 {
		t.Errorf("Minus().Len() = %d, want 2", n)
	}
	if n := a.Intersect(b).Len(); n != 1 {
		t.Errorf("Intersect().Len() = %d, want 1", n)
	}
	if added := a.Merge(b); added != 1 {
		t.Errorf("Merge() = %d new, want 1", added)
	}
	if a.Len() != 4 {
		t.Errorf("Len() after Merge = %d, want 4", a.Len())
	}
	if a.Minus(nil).Len() != 4 || a.Intersect(nil).Len() != 0 {
		t.Error("nil operand should behave as the empty set")
	}
}

// This is the regression test for the resume bug the shell suite found: a phase
// artifact must be reproducible from its own inputs. Writing the difference
// against the master list instead produced an empty artifact on the second run,
// and the merge that followed silently dropped every host the first run had found.
func TestArtifactIsKnownPlusNew(t *testing.T) {
	master := NewSet()
	master.AddAll([]string{"a.example.com", "b.example.com"})
	candidates := NewSet()
	candidates.AddAll([]string{"a.example.com", "b.example.com", "c.example.com"})

	artifact := func() *Set {
		known := candidates.Intersect(master)
		fresh := candidates.Minus(master) // only these need resolving
		out := NewSet()
		out.Merge(known)
		out.Merge(fresh)
		return out
	}

	first := artifact()
	if first.Len() != 3 {
		t.Fatalf("first pass wrote %d names, want 3", first.Len())
	}
	master.Merge(first)
	second := artifact() // the resumed run: every candidate is already known
	if second.Len() != 3 {
		t.Errorf("resumed pass wrote %d names, want 3", second.Len())
	}
}

func TestSetRoundTripAndMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "hosts.txt")

	s := NewSet()
	s.AddAll([]string{"z.example.com", "a.example.com", "not a host", "*.wild.example.com"})
	if err := s.WriteFile(path); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	back, err := LoadSet(path)
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if back.Len() != s.Len() {
		t.Errorf("round trip lost names: %d in, %d out", s.Len(), back.Len())
	}
	if !back.Has("wild.example.com") {
		t.Error("wildcard prefix should have been stripped on the way in")
	}

	// A missing artifact is an empty set, not an error — every phase output is
	// optional on a resumed run.
	empty, err := LoadSet(filepath.Join(dir, "absent.txt"))
	if err != nil || empty.Len() != 0 {
		t.Errorf("LoadSet(missing) = (%d, %v), want (0, nil)", empty.Len(), err)
	}

	// Nothing should be left behind by the atomic write.
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if e.Name() != "hosts.txt" {
			t.Errorf("temporary file survived the write: %s", e.Name())
		}
	}
}
