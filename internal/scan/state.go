package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// State is the resume record, and it is deliberately the same on-disk contract the
// shell implementation uses: one empty-ish marker file per completed phase under
// <run>/.state, plus a `complete` marker when the whole pipeline finished.
//
// Keeping the layouts identical is what lets the two implementations share a
// results directory — a run started with the shell pipeline can be finished by the
// binary and vice versa. A single richer state file would have been tidier and
// would have made that impossible.
type State struct {
	dir    string // <run>/.state
	target string
}

// OpenState creates the state directory for a run and records which target it
// belongs to.
//
// The target file is an addition the shell version does not write, so a run started
// there has none and is adopted without complaint. When it is present and
// disagrees, the run is refused: output directories are named after the target, but
// an operator who points --output at a directory holding another engagement would
// otherwise resume into it and produce a report mixing two clients.
func OpenState(runDir, target string) (*State, error) {
	s := &State{dir: filepath.Join(runDir, ".state"), target: target}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return nil, err
	}
	marker := filepath.Join(s.dir, "target")
	if b, err := os.ReadFile(marker); err == nil {
		if found := strings.TrimSpace(string(b)); found != "" && found != target {
			return nil, fmt.Errorf("%s holds a run against %q; refusing to resume it as %q",
				runDir, found, target)
		}
	}
	if err := os.WriteFile(marker, []byte(target+"\n"), 0o644); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *State) IsDone(id string) bool {
	_, err := os.Stat(filepath.Join(s.dir, id+".done"))
	return err == nil
}

// MarkDone flushes immediately rather than at the end of the run. The runs that
// need resuming are precisely the ones that were interrupted, so progress that is
// only in memory is progress that is lost.
func (s *State) MarkDone(id string) error {
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	return os.WriteFile(filepath.Join(s.dir, id+".done"), []byte(stamp+"\n"), 0o644)
}

func (s *State) MarkComplete() error {
	return os.WriteFile(filepath.Join(s.dir, "complete"), []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644)
}

func (s *State) Complete() bool {
	_, err := os.Stat(filepath.Join(s.dir, "complete"))
	return err == nil
}

// Count reports how many of ids are already done, for the resume banner.
func (s *State) Count(ids []string) int {
	n := 0
	for _, id := range ids {
		if s.IsDone(id) {
			n++
		}
	}
	return n
}

// Clear drops one phase's marker. `--only p6` means "run phase 6", so an already
// completed phase 6 has to be un-completed first; without this the flag silently
// does nothing on a resumed run, which is exactly when an operator reaches for it.
func (s *State) Clear(id string) error {
	err := os.Remove(filepath.Join(s.dir, id+".done"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Reset drops every marker so the next run starts from phase one. The artifacts
// themselves are left alone: re-running a phase overwrites its own output, and
// deleting results because somebody asked to re-run is not a trade anyone wants.
func (s *State) Reset() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.Name() == "target" {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, e.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// RunComplete reports whether the run directory at path finished, without opening
// state for it. Used when picking which previous run to resume or diff against.
func RunComplete(runDir string) bool {
	_, err := os.Stat(filepath.Join(runDir, ".state", "complete"))
	return err == nil
}
