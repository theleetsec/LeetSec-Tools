package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/theleetsec/LeetSec-Tools/internal/host"
	"github.com/theleetsec/LeetSec-Tools/internal/ui"
)

// Options is the run request, filled in by the CLI.
//
// A struct rather than a positional argument list because the shell version threaded
// nine positional parameters through three layers and produced two argument-order
// bugs doing it.
type Options struct {
	Target   string
	OutRoot  string
	Profile  string   // "" to size from the machine, or lite/balanced/beast
	Wordlist string   // overrides the cached brute-force list
	Deep     bool     // include low and info severity findings
	Fresh    bool     // ignore any resumable run and start from phase one
	Offline  bool     // never fetch wordlists; use whatever is cached
	Only     []string // phase ids to run, to the exclusion of the rest
	Skip     []string // phase ids to skip
	DryRun   bool     // print the commands, execute nothing
	SubsOnly bool     // subdomain hunt only: skip ports, nuclei, screenshots
}

// Pipeline owns one run: where it writes, what it may spend, and how far it got.
type Pipeline struct {
	opt  Options
	h    host.Info
	con  *ui.Console
	prof Profile
	L    *Layout
	st   *State
	run  *Runner
	wl   Wordlists

	only map[string]bool
	skip map[string]bool

	phaseMu  sync.Mutex
	phaseErr error
}

// phase is one entry in the graph.
//
// Keeping the table separate from the phase bodies is what lets --only, --skip, the
// resume banner and the help text talk about phases without any of them holding
// their own copy of the list. The shell had the ids written out in four places and
// they disagreed about which ids existed.
type phase struct {
	id    string
	title string
	fn    func(*Pipeline, context.Context) error
}

func phases() []phase {
	return []phase{
		{"p1", "Passive intel", (*Pipeline).phasePassive},
		{"p2", "Brute force", (*Pipeline).phaseBrute},
		{"p3", "Recursive brute force", (*Pipeline).phaseRecursive},
		{"p4", "Permutations", (*Pipeline).phasePermute},
		{"p5", "HTTP probing", (*Pipeline).phaseHTTP},
		{"p6", "Port scanning", (*Pipeline).phasePorts},
		{"p7", "Crawling", (*Pipeline).phaseCrawl},
		{"p8", "Vulnerability scan", (*Pipeline).phaseVulns},
		{"p9", "Screenshots", (*Pipeline).phaseScreenshots},
	}
}

// PhaseIDs is the ordered id list, for help text and flag validation.
func PhaseIDs() []string {
	out := make([]string, 0, len(phases()))
	for _, ph := range phases() {
		out = append(out, ph.id)
	}
	return out
}

// PhaseTitle returns the human name for an id, or "" when the id is not one.
func PhaseTitle(id string) string {
	for _, ph := range phases() {
		if ph.id == id {
			return ph.title
		}
	}
	return ""
}

// PhaseList is the "p1 passive, p2 brute, ..." line the CLI prints under --help.
func PhaseList() string {
	var b strings.Builder
	for i, ph := range phases() {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "    %-4s %s", ph.id, ph.title)
	}
	return b.String()
}

// New validates the request and prepares the run directory. It does no network and
// runs no tools, so a bad invocation fails before anything is written.
func New(opt Options, h host.Info, con *ui.Console) (*Pipeline, error) {
	target, ok := CleanTarget(opt.Target)
	if !ok {
		return nil, fmt.Errorf("%q is not a domain name", opt.Target)
	}
	opt.Target = target

	for _, id := range append(append([]string{}, opt.Only...), opt.Skip...) {
		if PhaseTitle(id) == "" {
			return nil, fmt.Errorf("unknown phase %q: expected one of %s",
				id, strings.Join(PhaseIDs(), " "))
		}
	}

	prof, err := PickProfile(opt.Profile, h)
	if err != nil {
		return nil, err
	}
	p := &Pipeline{
		opt: opt, h: h, con: con, prof: prof,
		only: idSet(opt.Only), skip: idSet(opt.Skip),
	}
	if opt.DryRun {
		// Paths are labels for the plan. Do not inspect, create or adopt any run.
		base := filepath.Join(opt.OutRoot, "recon_"+target)
		run := filepath.Join(base, "<run>")
		p.L = &Layout{Base: base, Run: run, Reports: filepath.Join(run, "reports"),
			Logs: filepath.Join(run, "logs"), Work: "<scratch>"}
		return p, nil
	}
	l, err := NewLayout(target, opt.OutRoot, opt.Fresh, h)
	if err != nil {
		return nil, err
	}
	if len(opt.Only) > 0 && !l.Resumed && l.PrevRun != "" {
		if err := l.CopyInputs(l.PrevRun); err != nil {
			l.Cleanup()
			return nil, fmt.Errorf("copying previous scan inputs: %w", err)
		}
	}
	// The transcript belongs with the run it describes, which is why the console is
	// constructed without one and given it here.
	if err := con.SetLog(filepath.Join(l.Logs, "leetenum.log")); err != nil {
		con.Warn(err.Error())
	}
	st, err := OpenState(l.Run, target)
	if err != nil {
		l.Cleanup()
		return nil, err
	}
	if opt.Fresh {
		if err := st.Reset(); err != nil {
			return nil, err
		}
	}

	p.L, p.st = l, st
	p.run = &Runner{
			LogDir: l.Logs,
			DryRun: opt.DryRun,
			// The tools inherit NO_COLOR so escape sequences stay out of the
			// artifacts. A findings file with ANSI codes in it is not greppable and
			// looks like corruption when pasted into a report.
			Env: []string{"NO_COLOR=1"},
			OnResult: p.recordResult,
		}
	return p, nil
}

func idSet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// Run executes the graph, then rebuilds the merged results, diffs against the
// previous run and writes the report.
//
// Two rules hold the resume contract together. A phase is marked done only when it
// returns nil, so an interrupted or failing phase is retried rather than skipped
// forever. And a cancelled context stops the run immediately, leaving the markers
// that were already flushed — Ctrl-C on hour six of a scan must cost the current
// phase, not the five before it.
func (p *Pipeline) Run(ctx context.Context) error {
	if p.opt.DryRun {
		return p.dryPlan(ctx)
	}
	defer p.L.Cleanup()

	wl, err := PrepareWordlists(ctx, p.con, p.opt.Wordlist, p.opt.Offline)
	if err != nil {
		return err
	}
	p.wl = wl
	p.plan()

	all := phases()
	var failed []string
	for i, ph := range all {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !p.wanted(ph.id) {
			continue
		}
		// An explicitly requested phase is re-run even if it completed earlier,
		// which is the entire point of asking for it by name.
		if len(p.only) > 0 {
			if err := p.st.Clear(ph.id); err != nil {
				return err
			}
		}
		if p.st.IsDone(ph.id) {
			p.con.Phase(i+1, len(all), ph.title+" — already done")
			continue
		}
		p.con.Phase(i+1, len(all), ph.title)
		if err := p.runPhase(ctx, ph); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			p.con.Err(fmt.Sprintf("%s did not complete: %v", ph.id, err))
			p.con.Info("It will be retried on the next run; the rest of the scan continues.")
			failed = append(failed, ph.id)
			continue
		}
		if err := p.st.MarkDone(ph.id); err != nil {
			return err
		}
	}

	if err := p.finish(ctx); err != nil {
		return err
	}
	if len(failed) > 0 {
		return fmt.Errorf("incomplete phases: %s; re-run the same command to retry", strings.Join(failed, ", "))
	}
	return nil
}

// runPhase combines artifact errors with all subprocess outcomes. Some sources
// keep partial results after an error, so relying on the phase's return value
// alone would incorrectly checkpoint a failed or interrupted tool.
func (p *Pipeline) runPhase(ctx context.Context, ph phase) error {
	p.phaseMu.Lock()
	p.phaseErr = nil
	p.phaseMu.Unlock()
	err := ph.fn(p, ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	p.phaseMu.Lock()
	defer p.phaseMu.Unlock()
	return errors.Join(err, p.phaseErr)
}

func (p *Pipeline) recordResult(res Result) {
	if res.Err == nil || res.TimedOut {
		return // bounded commands deliberately keep their partial output
	}
	p.phaseMu.Lock()
	defer p.phaseMu.Unlock()
	if p.phaseErr == nil {
		p.phaseErr = fmt.Errorf("%s failed: %w", formatCommand(res.Cmd), res.Err)
	}
}

// finish rebuilds the merged view of everything on disk, compares it against the
// previous run and writes the report.
//
// The rebuild is unconditional and reads only artifacts, never in-memory state, so a
// run that resumed at phase 8 produces the same master list as one that ran all nine
// phases in a row. That property is the whole reason resume can be trusted.
func (p *Pipeline) finish(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	master, err := p.rebuildMaster()
	if err != nil {
		return err
	}
	fresh, err := p.diffPrevious(master)
	if err != nil {
		return err
	}
	if err := p.writeReport(master, fresh); err != nil {
		return err
	}
	p.linkLatest()

	// `complete` is what stops the next invocation resuming into this directory and
	// what makes it eligible as a differential baseline, so it is only written when
	// every phase was either run or deliberately skipped. A --only run, or one that
	// was interrupted, stays resumable.
	if ctx.Err() == nil && p.allSatisfied() {
		return p.st.MarkComplete()
	}
	return nil
}

func (p *Pipeline) allSatisfied() bool {
	if len(p.only) > 0 {
		return false
	}
	for _, ph := range phases() {
		if !p.wanted(ph.id) {
			continue
		}
		if !p.st.IsDone(ph.id) {
			return false
		}
	}
	return true
}

// linkLatest points <base>/latest at this run. The link is relative so the whole
// output tree can be moved or archived, with a plain-file fallback for filesystems
// that cannot symlink — some network mounts, and anything shared with Windows.
func (p *Pipeline) linkLatest() {
	link := filepath.Join(p.L.Base, "latest")
	_ = os.Remove(link)
	if err := os.Symlink(filepath.Base(p.L.Run), link); err != nil {
		_ = os.WriteFile(filepath.Join(p.L.Base, "latest.txt"), []byte(p.L.Run+"\n"), 0o644)
	}
}

// plan prints what is about to happen. It exists because the single most common
// support question about the original was "is it doing anything, and against what?"
func (p *Pipeline) plan() {
	depth := "standard"
	if p.opt.Deep {
		depth = "deep (includes low and info)"
	}
	p.con.SummaryOpen("Scan plan")
	p.con.SummaryRow("Target", p.opt.Target, ui.LevelNone)
	p.con.SummaryRow("Profile", fmt.Sprintf("%s — DNS %d/s, HTTP %d threads, fanout %d",
		p.prof.Name, p.prof.DNSRate, p.prof.HTTPXThreads, p.prof.Fanout), ui.LevelNone)
	p.con.SummaryRow("Machine", p.h.String(), ui.LevelNone)
	p.con.SummaryRow("Depth", depth, ui.LevelNone)
	p.con.SummaryRow("Output", p.L.Run, ui.LevelNone)
	p.con.SummaryRow("Scratch", p.L.Work, ui.LevelNone)
	if p.opt.Wordlist != "" {
		p.con.SummaryRow("Wordlist", p.opt.Wordlist, ui.LevelNone)
	}
	if p.L.Resumed {
		p.con.SummaryRow("Resuming", p.doneList(), ui.LevelOK)
	}
	if p.L.PrevMaster != "" {
		p.con.SummaryRow("Comparing against", filepath.Base(filepath.Dir(p.L.PrevMaster)), ui.LevelNone)
	}
	if len(p.only) > 0 {
		p.con.SummaryRow("Only", strings.Join(p.opt.Only, " "), ui.LevelWarn)
	}
	if len(p.skip) > 0 {
		p.con.SummaryRow("Skipping", strings.Join(p.opt.Skip, " "), ui.LevelWarn)
	}
	if p.opt.DryRun {
		p.con.SummaryRow("Dry run", "no commands will be executed", ui.LevelWarn)
	}
	if p.opt.SubsOnly {
		p.con.SummaryRow("Mode", "subdomains only (no ports, nuclei, screenshots)", ui.LevelNone)
	}
	p.con.SummaryClose()
}

func (p *Pipeline) doneList() string {
	var done []string
	for _, ph := range phases() {
		if p.st.IsDone(ph.id) {
			done = append(done, ph.id)
		}
	}
	if len(done) == 0 {
		return "nothing yet"
	}
	return strings.Join(done, " ") + " already complete"
}

// wanted applies --only and --skip. --only wins, because an operator who named a
// phase has said what they want more precisely than one who named an exclusion.
func (p *Pipeline) wanted(id string) bool {
	if p.opt.SubsOnly {
		switch id {
		case "p6", "p8", "p9":
			return false
		}
	}
	if len(p.only) > 0 {
		return p.only[id]
	}
	return !p.skip[id]
}

// need reports whether a tool is available, saying so when it is not.
//
// Naming the missing tool and the phase it costs is the whole improvement over the
// original `command -v x >/dev/null && ...`, which skipped in silence and left a run
// that looked complete. Under --dry-run every tool is treated as present, so the
// transcript shows the full graph rather than only the parts this machine could run.
func (p *Pipeline) need(bin, what string) bool {
	if p.opt.DryRun || host.Have(bin) {
		return true
	}
	p.con.Warn(fmt.Sprintf("%s is not installed — skipping %s", bin, what))
	return false
}

// exec runs one command inside a console step, so every external tool produces
// exactly one line of terminal output carrying its outcome and duration.
func (p *Pipeline) exec(ctx context.Context, label, logName, outPath string, cmd ...string) Result {
	st := p.con.Start(label)
	return p.report(st, p.run.Run(ctx, logName, outPath, cmd...))
}

// report reduces a Result to the one terminal line each tool is allowed. It is
// separate from exec so a phase that needs its own runner — phase 8 attaches standard
// input — still produces an identically shaped step line.
func (p *Pipeline) report(st *ui.Step, res Result) Result {
	switch {
	case res.Err == nil:
		note := ""
		if res.Lines > 0 {
			note = fmt.Sprintf("%d lines", res.Lines)
		}
		st.OK(note)
	case res.TimedOut:
		// A time budget being hit is not a failure. Every bounded phase keeps what
		// the tool produced before the deadline, which on a large target is most of
		// it.
		st.Failed(fmt.Sprintf("stopped at its %s budget; keeping partial output",
			res.Took.Round(time.Second)))
	default:
		msg := res.Err.Error()
		if res.LogPath != "" {
			msg += " — see logs/" + filepath.Base(res.LogPath)
		}
		st.Failed(msg)
	}
	return res
}

// budget bounds one command in wall-clock time. Recon tools have no natural end:
// amass on a large target and katana on a single-page app both run until stopped, and
// the original had no ceiling on either, which is how a scan reached day three.
func budget(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}

// masterInputs are the phase artifacts that contribute resolved hostnames. Phase 7
// is in the list because crawling finds names that DNS enumeration never sees —
// hosts referenced only in a JavaScript bundle, a CSP header or a redirect chain.
var masterInputs = []string{
	"01_passive.txt", "02_brute.txt", "03_recursive.txt", "04_perms.txt",
	"05_tls_hosts.txt", "07_crawled_hosts.txt", "07_deep_hosts.txt",
}

// seedInputs are everything discovered before permutations, used as permutation
// seeds and as recursion parents.
var seedInputs = []string{"01_passive.txt", "02_brute.txt", "03_recursive.txt"}

// rebuildMaster merges every artifact that exists into the in-scope master list.
//
// Derived state is rebuilt from files, never from variables a skipped phase would
// have set. That is the correctness rule the shell version broke: on a resumed run
// its counts came from state that phase 1 had populated, so resuming at phase 6
// reported zero hostnames and probed nothing.
func (p *Pipeline) rebuildMaster() (*Set, error) {
	m, err := p.mergeArtifacts(masterInputs)
	if err != nil {
		return nil, err
	}
	if err := m.WriteFile(p.L.Master()); err != nil {
		return nil, err
	}
	return m, nil
}

func (p *Pipeline) seeds() (*Set, error) { return p.mergeArtifacts(seedInputs) }

func (p *Pipeline) mergeArtifacts(names []string) (*Set, error) {
	out := NewSet()
	for _, n := range names {
		s, err := LoadSet(p.L.Path(n))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", n, err)
		}
		out.Merge(s)
	}
	return out.InScope(p.opt.Target), nil
}

// save normalises, scope-filters and atomically writes one phase artifact from
// whatever files the tools produced.
//
// Every durable artifact goes through here, which is what guarantees they are all
// lowercase, deduplicated, byte-sorted and free of the wildcard prefixes and trailing
// dots the various tools emit. It is also the scope gate: a name that a third-party
// source volunteered outside the engagement cannot reach a client report, however it
// arrived.
func (p *Pipeline) save(dst string, srcs ...string) (int, error) {
	s := NewSet()
	for _, src := range srcs {
		loaded, err := LoadSet(src)
		if err != nil {
			return 0, err
		}
		s.Merge(loaded)
	}
	s = s.InScope(p.opt.Target)
	if err := s.WriteFile(dst); err != nil {
		return 0, err
	}
	return s.Len(), nil
}

// empty writes zero-length artifacts for a phase that could not run.
//
// The file has to exist: downstream phases and the resume logic both read artifacts
// to decide what to do, and "absent" and "empty" have to mean the same thing to them
// or a skipped phase changes the behaviour of the next one.
func (p *Pipeline) empty(paths ...string) error {
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

// liveTargets merges standard-port services from phase 5 with services phase 6
// found on another port. It is rebuilt from disk each time, so phases 7 to 9 work
// on a resumed run where probing and port scanning were already done.
//
// The returned path is a scratch file because it is an input to other tools, not a
// result; master_live_urls.txt in the run directory is the durable copy.
func (p *Pipeline) liveTargets() (string, []string, error) {
	var all []string
	for _, n := range []string{"05_live_urls.txt", "06_extra_urls.txt"} {
		lines, err := LoadLines(p.L.Path(n))
		if err != nil {
			return "", nil, err
		}
		all = append(all, lines...)
	}
	all = KeepHTTP(all)
	path := p.L.Temp("live_urls.txt")
	if err := WriteLines(path, all); err != nil {
		return "", nil, err
	}
	// WriteLines deduplicates, so read back the count rather than trusting len(all).
	final, err := LoadLines(path)
	return path, final, err
}

func itoa(n int) string { return strconv.Itoa(n) }
