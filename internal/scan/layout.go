package scan

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/theleetsec/LeetSec-Tools/internal/host"
)

// Profile is the concurrency and rate budget for a run. It exists because the same
// pipeline has to be usable on a 1 GB VPS and on a 32-core workstation, and the
// numbers that make one fast make the other run out of memory or get rate-limited
// into returning nothing.
type Profile struct {
	Name         string
	HTTPXThreads int
	DNSRate      int
	NaabuRate    int
	Fanout       int
	RecWords     int
	PermSeeds    int
	KatanaConc   int
}

// DNSRatePerWorker keeps total DNS traffic at DNSRate no matter how many recursive
// workers are running. Multiplying the rate by the fanout is how the original
// version got resolvers to start dropping queries, which looks exactly like a
// target with no subdomains.
func (p Profile) DNSRatePerWorker() int {
	f := p.Fanout
	if f < 1 {
		f = 1
	}
	if r := p.DNSRate / f; r > 50 {
		return r
	}
	return 50
}

// PickProfile chooses a budget from the machine, or validates a forced choice.
// Unknown memory (RAMMB == 0) sizes from cores alone rather than assuming the
// smallest profile, because the platforms where the probe fails are not
// necessarily small ones.
func PickProfile(forced string, h host.Info) (Profile, error) {
	name := strings.ToLower(strings.TrimSpace(forced))
	// "auto" is what the CLI's --profile defaults to and what an operator types when
	// they want the machine sized for them, so it means the same as asking for nothing.
	if name == "auto" {
		name = ""
	}
	if name == "" {
		switch {
		case h.RAMMB >= 32768 && h.Cores >= 8, h.RAMMB == 0 && h.Cores >= 16:
			name = "beast"
		case h.RAMMB >= 7168 && h.Cores >= 4, h.RAMMB == 0 && h.Cores >= 4:
			name = "balanced"
		default:
			name = "lite"
		}
	}
	switch name {
	case "beast":
		return Profile{"beast", 300, 15000, 3000, h.Cores * 2, 50000, 50000, 20}, nil
	case "balanced":
		return Profile{"balanced", 120, 5000, 1500, h.Cores, 20000, 20000, 10}, nil
	case "lite":
		return Profile{"lite", 40, 1000, 500, 2, 5000, 5000, 5}, nil
	}
	return Profile{}, fmt.Errorf("unknown profile %q: expected lite, balanced or beast", forced)
}

// Layout is where a run writes. Everything durable lives under Run, including each
// phase's own artifact, so resuming never depends on scratch space having survived
// a reboot; Work is disposable and may be tmpfs.
type Layout struct {
	Base       string // <outroot>/recon_<target>
	Run        string // <base>/<timestamp>, or the directory being resumed
	Reports    string
	Logs       string
	Work       string
	PrevMaster string // newest completed run's master list, for differential mode
	PrevRun    string // newest completed run, for --only input reuse
	Resumed    bool
}

// NewLayout picks the run directory and creates the tree.
//
// The choice of directory is made before anything is written, which is the only
// point at which "the newest previous run" is unambiguous — deciding it later, after
// the new directory exists, is what made the original differential mode compare a
// run against itself.
func NewLayout(target, outRoot string, fresh bool, h host.Info) (*Layout, error) {
	l := &Layout{Base: filepath.Join(outRoot, "recon_"+target)}
	if err := os.MkdirAll(l.Base, 0o755); err != nil {
		return nil, err
	}

	runs, err := previousRuns(l.Base)
	if err != nil {
		return nil, err
	}

	if !fresh && len(runs) > 0 && !RunComplete(runs[0]) {
		// Resuming: the incomplete newest run is the directory, by definition.
		l.Run = runs[0]
		l.Resumed = true
	} else {
		// A fresh directory. The stamp is second-granular, so a run that finishes
		// inside one second — --dry-run, --only p9 with nothing live, any scripted
		// re-invoke — collides with the run before it. Landing on a *completed*
		// directory is the damaging case: Resumed stays false so nothing warns, the
		// finished artifacts are written over, and previousRuns skips d == l.Run so
		// PrevMaster comes back empty and the differential baseline is lost silently.
		//
		// Advancing the stamp a second at a time keeps the 15-character format that
		// isRunStamp requires; a "-2" suffix would make the directory invisible to
		// previousRuns and break resume a different way.
		l.Run = freeRunDir(l.Base, time.Now())
	}

	for _, d := range runs {
		if d == l.Run || !RunComplete(d) {
			continue
		}
		if l.PrevRun == "" {
			l.PrevRun = d
		}
		m := filepath.Join(d, "master_dns.txt")
		if fi, err := os.Stat(m); err == nil && fi.Size() > 0 {
			l.PrevMaster = m
			break
		}
	}

	l.Reports = filepath.Join(l.Run, "reports")
	l.Logs = filepath.Join(l.Run, "logs")
	for _, d := range []string{l.Run, l.Reports, l.Logs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	l.Work, err = os.MkdirTemp(h.Scratch, "leetenum-"+target+"-")
	if err != nil {
		// Scratch is an optimisation, not a requirement. Falling back into the run
		// directory costs speed on a tmpfs-less host and nothing else.
		l.Work = filepath.Join(l.Run, ".work")
		if err := os.MkdirAll(l.Work, 0o755); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// CopyInputs starts a selective rerun from durable phase inputs. It copies files,
// never links them, and does not copy checkpoints or reports: the completed run
// remains the comparison baseline and the new run records its own work.
func (l *Layout) CopyInputs(previous string) error {
	names := append(append([]string{}, masterInputs...),
		"05_http.jsonl", "05_live_urls.txt", "06_ports.txt", "06_extra_urls.txt", "07_urls.txt")
	names = append(names, crawlProgressFiles...)
	names = append(names, "01_candidates.txt", "01_unresolved.txt", "07_candidates.txt", "07_unresolved.txt")
	for _, name := range names {
		src, err := os.Open(filepath.Join(previous, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		info, err := src.Stat()
		if err != nil || !info.Mode().IsRegular() {
			src.Close()
			return fmt.Errorf("previous artifact %s is not a readable regular file", name)
		}
		dst, err := os.OpenFile(l.Path(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
		if err != nil {
			src.Close()
			return err
		}
		_, copyErr := io.Copy(dst, src)
		src.Close()
		closeErr := dst.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// freeRunDir returns the first unused run directory at or after start.
//
// Bounded rather than unbounded: a caller that has somehow filled every second for
// an hour has a different problem, and an infinite loop inside directory selection
// would hang the run before it printed anything. Falling back to the last candidate
// preserves the previous behaviour in that impossible case instead of failing.
func freeRunDir(base string, start time.Time) string {
	const maxProbe = 3600
	dir := filepath.Join(base, start.Format(runStampFormat))
	for i := 0; i < maxProbe; i++ {
		dir = filepath.Join(base, start.Add(time.Duration(i)*time.Second).Format(runStampFormat))
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return dir
		}
	}
	return dir
}

// previousRuns lists run directories under base, newest first.
//
// The stamp format sorts lexicographically in the same order it sorts
// chronologically, so a reverse string sort is the date sort, with no parsing and no
// dependence on the filesystem's directory order — which is not sorted on ext4 and
// differs again on APFS.
//
// isRunStamp is the reason this does not simply take every subdirectory: `reports`,
// `logs` and `.work` all live next to the run directories in older trees, and
// treating one of them as the newest run means resuming into it.
func previousRuns(base string) ([]string, error) {
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && isRunStamp(e.Name()) {
			out = append(out, filepath.Join(base, e.Name()))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

// runStampFormat is the run directory name. isRunStamp below and freeRunDir above
// both depend on its exact width, so it lives in one place: a format change that
// altered the length would make every existing run invisible to previousRuns, which
// silently disables both resume and differential reporting.
const runStampFormat = "20060102_150405"

// runStampLen is len(runStampFormat) — 15. Asserted by TestRunStampLen rather than
// hardcoded twice.
const runStampLen = len(runStampFormat)

// isRunStamp matches exactly 20060102_150405 and nothing else.
func isRunStamp(name string) bool {
	if len(name) != runStampLen || name[8] != '_' {
		return false
	}
	for i, r := range name {
		if i == 8 {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Path returns a durable artifact path inside the run directory.
func (l *Layout) Path(name string) string { return filepath.Join(l.Run, name) }

// Report returns a path inside the reports directory, which is the subset an
// operator is expected to read rather than the raw phase output.
func (l *Layout) Report(name string) string { return filepath.Join(l.Reports, name) }

// Temp returns a scratch path. Nothing under here may be needed by a later phase or
// by a resumed run.
func (l *Layout) Temp(name string) string { return filepath.Join(l.Work, name) }

// Master is the merged, deduplicated, in-scope name list: the one file that carries
// forward between runs, both as the resume baseline and as the previous side of a
// differential comparison.
func (l *Layout) Master() string { return l.Path("master_dns.txt") }

// Cleanup removes the scratch directory. It is safe to call twice, and safe to call
// when Work fell back inside the run directory, because in that case the fallback
// path is `.work` and holds nothing a resume reads.
func (l *Layout) Cleanup() {
	if l.Work != "" {
		_ = os.RemoveAll(l.Work)
	}
}
