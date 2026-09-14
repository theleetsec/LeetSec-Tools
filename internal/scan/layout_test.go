package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/theleetsec/LeetSec-Tools/internal/host"
)

func TestPickProfileFromHost(t *testing.T) {
	cases := []struct {
		name  string
		h     host.Info
		want  string
		cores int
	}{
		{"workstation", host.Info{Cores: 16, RAMMB: 65536}, "beast", 32},
		{"vps", host.Info{Cores: 4, RAMMB: 8192}, "balanced", 4},
		{"tiny vps", host.Info{Cores: 1, RAMMB: 1024}, "lite", 2},
		// Plenty of RAM but too few cores is not a beast: the phases that make
		// beast worth choosing are the parallel ones.
		{"lopsided", host.Info{Cores: 2, RAMMB: 65536}, "lite", 2},
		// RAMMB == 0 means the probe failed, not that the machine is small. A
		// 16-core box with an unreadable meminfo should not be throttled to lite.
		{"unknown ram, many cores", host.Info{Cores: 16}, "beast", 32},
		{"unknown ram, few cores", host.Info{Cores: 4}, "balanced", 4},
		{"unknown ram, one core", host.Info{Cores: 1}, "lite", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := PickProfile("", c.h)
			if err != nil {
				t.Fatal(err)
			}
			if p.Name != c.want {
				t.Errorf("%d cores / %d MB: chose %q, want %q", c.h.Cores, c.h.RAMMB, p.Name, c.want)
			}
			if p.Fanout != c.cores {
				t.Errorf("fanout %d, want %d", p.Fanout, c.cores)
			}
		})
	}
}

func TestPickProfileForced(t *testing.T) {
	small := host.Info{Cores: 1, RAMMB: 512}
	// A forced profile overrides the probe: an operator who knows the box can
	// take it, or knows the target cannot, outranks the heuristic.
	for _, n := range []string{"beast", "BALANCED", " lite "} {
		p, err := PickProfile(n, small)
		if err != nil {
			t.Fatalf("%q: %v", n, err)
		}
		if p.Name == "" {
			t.Errorf("%q produced an unnamed profile", n)
		}
	}
	if _, err := PickProfile("turbo", small); err == nil {
		t.Error("unknown profile name was accepted")
	}
}

// The per-worker divisor is the guard against the failure that looks like a target
// with no subdomains: fanout workers each running at the full DNS rate is fanout
// times the intended traffic, and resolvers answer that by dropping queries.
func TestDNSRatePerWorkerHoldsTheBudget(t *testing.T) {
	p, err := PickProfile("beast", host.Info{Cores: 16, RAMMB: 65536})
	if err != nil {
		t.Fatal(err)
	}
	if total := p.DNSRatePerWorker() * p.Fanout; total > p.DNSRate {
		t.Errorf("%d workers x %d = %d queries/s, budget is %d",
			p.Fanout, p.DNSRatePerWorker(), total, p.DNSRate)
	}
	// The floor matters in the other direction: a lite profile split across
	// workers must not fall to a rate that would take hours per wordlist.
	lite, _ := PickProfile("lite", host.Info{})
	if lite.DNSRatePerWorker() < 50 {
		t.Errorf("per-worker rate %d fell below the floor", lite.DNSRatePerWorker())
	}
	zero := Profile{Name: "odd", DNSRate: 1000, Fanout: 0}
	if got := zero.DNSRatePerWorker(); got != 1000 {
		t.Errorf("fanout 0 gave %d, want the full rate rather than a divide by zero", got)
	}
}

func TestIsRunStamp(t *testing.T) {
	good := []string{"20260901_143000", "19700101_000000"}
	bad := []string{"reports", "logs", ".work", "2026090_143000", "20260901-143000",
		"20260901_1430000", "master_dns.txt", ""}
	for _, s := range good {
		if !isRunStamp(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range bad {
		if isRunStamp(s) {
			t.Errorf("%q accepted as a run directory", s)
		}
	}
}

// Directory selection is where the original differential mode went wrong, so this
// asserts all three outcomes: a first run is fresh, an interrupted run is adopted,
// and a completed run becomes the previous side of the comparison rather than the
// directory written into.
func TestLayoutResumeAndPrevMaster(t *testing.T) {
	root := t.TempDir()
	h := host.Info{Scratch: t.TempDir()}

	first, err := NewLayout("example.com", root, false, h)
	if err != nil {
		t.Fatal(err)
	}
	if first.Resumed {
		t.Error("a first run reported itself as resumed")
	}
	if first.PrevMaster != "" {
		t.Errorf("a first run found a previous master at %s", first.PrevMaster)
	}
	if filepath.Base(first.Base) != "recon_example.com" {
		t.Errorf("base directory is %s", first.Base)
	}
	for _, d := range []string{first.Run, first.Reports, first.Logs, first.Work} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Errorf("%s was not created", d)
		}
	}

	// Interrupt it: state exists, `complete` does not.
	st, err := OpenState(first.Run, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkDone("p1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first.Master(), []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	resumed, err := NewLayout("example.com", root, false, h)
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.Resumed || resumed.Run != first.Run {
		t.Fatalf("interrupted run at %s was not adopted (got %s, resumed=%v)",
			first.Run, resumed.Run, resumed.Resumed)
	}
	// Its own master must not become its own baseline.
	if resumed.PrevMaster != "" {
		t.Errorf("resumed run took %s as its previous master", resumed.PrevMaster)
	}

	// Finish it, then start a genuinely new run.
	if err := st.MarkComplete(); err != nil {
		t.Fatal(err)
	}
	next, err := NewLayout("example.com", root, false, h)
	if err != nil {
		t.Fatal(err)
	}
	if next.Resumed {
		t.Error("resumed into a completed run")
	}
	if next.Run == first.Run {
		t.Fatal("a completed run was written into a second time")
	}
	if next.PrevMaster != first.Master() {
		t.Errorf("previous master is %q, want %q", next.PrevMaster, first.Master())
	}

	// --fresh ignores an interrupted run rather than adopting it.
	fresh, err := NewLayout("example.com", root, true, h)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Resumed {
		t.Error("--fresh still resumed")
	}
}

// An empty master is not a baseline. A run that was interrupted before phase two
// leaves a zero-byte file behind, and diffing against it reports every name on the
// target as newly discovered.
func TestLayoutSkipsEmptyPrevMaster(t *testing.T) {
	root := t.TempDir()
	h := host.Info{Scratch: t.TempDir()}
	base := filepath.Join(root, "recon_example.com")

	older := filepath.Join(base, "20260101_000000")
	newer := filepath.Join(base, "20260201_000000")
	for _, d := range []string{older, newer} {
		if err := os.MkdirAll(filepath.Join(d, ".state"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, ".state", "complete"), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(older, "master_dns.txt"), []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newer, "master_dns.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	l, err := NewLayout("example.com", root, false, h)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(older, "master_dns.txt"); l.PrevMaster != want {
		t.Errorf("previous master is %q, want the newest non-empty one %q", l.PrevMaster, want)
	}
}

// Scratch is an optimisation. An unwritable scratch directory must cost speed, not
// the run: this is the low-spec VPS with no /dev/shm and a read-only /tmp mount.
func TestLayoutFallsBackWhenScratchUnusable(t *testing.T) {
	root := t.TempDir()
	l, err := NewLayout("example.com", root, false, host.Info{Scratch: filepath.Join(root, "nope")})
	if err != nil {
		t.Fatalf("unusable scratch failed the run: %v", err)
	}
	if fi, err := os.Stat(l.Work); err != nil || !fi.IsDir() {
		t.Fatalf("no work directory after fallback: %v", err)
	}
	if filepath.Dir(l.Work) != l.Run {
		t.Errorf("fallback work directory is %s, want it inside %s", l.Work, l.Run)
	}
	l.Cleanup()
	if _, err := os.Stat(l.Work); !os.IsNotExist(err) {
		t.Error("Cleanup left the work directory behind")
	}
	l.Cleanup() // must be safe twice
}
