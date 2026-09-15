package scan

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/theleetsec/LeetSec-Tools/internal/host"
)

// The nine phases. Each one writes exactly one durable artifact (two where the data
// genuinely has two shapes), returns nil when it is finished — including when it was
// skipped for a missing tool — and returns an error only when something went wrong
// that a retry might fix. The caller marks a phase done on nil, so an error here means
// the phase runs again next time.

// ---------------------------------------------------------------------------
// Phase 1 — passive sources
//
// Nothing here touches the target. It is the cheapest phase and the one most likely
// to find hosts that no amount of brute forcing would, so it runs first and its
// output seeds everything after it.
// ---------------------------------------------------------------------------

func (p *Pipeline) phasePassive(ctx context.Context) error {
	art := p.L.Path("01_passive.txt")
	candidates := NewSet()

	if p.need("subfinder", "subfinder") {
		out := p.L.Temp("subfinder.txt")
		p.execOptional(ctx, "subfinder", "subfinder", "",
			"subfinder", "-d", p.opt.Target, "-all", "-silent", "-o", out)
		p.absorb(candidates, out)
	}

	if p.need("assetfinder", "assetfinder") {
		// assetfinder has no output flag; the runner captures stdout to the file,
		// which is where the shell version needed a redirect and therefore a shell.
		out := p.L.Temp("assetfinder.txt")
		p.execOptional(ctx, "assetfinder", "assetfinder", out,
			"assetfinder", "--subs-only", p.opt.Target)
		p.absorb(candidates, out)
	}

	p.amass(ctx, candidates)

	if p.need("findomain", "findomain") {
		out := p.L.Temp("findomain.txt")
		p.execOptional(ctx, "findomain", "findomain", out,
			"findomain", "-t", p.opt.Target, "-q")
		p.absorb(candidates, out)
	} else {
		p.optionalWarning("findomain: not installed; other passive sources remain enabled")
	}

	p.pullAPIs(ctx, candidates)
	p.fromAPI(ctx, candidates, "DNS records (NS/MX/TXT/SPF)", DNSIntel)
	p.fromAPI(ctx, candidates, "DNS zone transfer", AXFR)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if candidates.Len() == 0 && p.sourceOK == 0 {
		return fmt.Errorf("no passive source completed successfully; see optional-warnings.log")
	}

	p.con.SetStat("names", candidates.Len())
	return p.resolveInto(ctx, art, candidates, "passive")
}

// pullAPIs runs the keyless HTTP sources in parallel. One console step covers
// the whole fan-out so the screen stays a dashboard rather than many stacked
// spinners. A single source failing does not fail the rest.
func (p *Pipeline) pullAPIs(ctx context.Context, into *Set) {
	if p.opt.DryRun {
		p.con.Start("passive APIs").Skipped("dry run")
		return
	}
	st := p.con.Start("passive APIs (crt.sh, wayback, otx, …)")
	type result struct {
		label string
		set   *Set
		err   error
	}
	ch := make(chan result, len(extraAPIs()))
	var wg sync.WaitGroup
	for _, src := range extraAPIs() {
		wg.Add(1)
		go func(label string, fn func(context.Context, string) (*Set, error)) {
			defer wg.Done()
			found, err := fn(ctx, p.opt.Target)
			ch <- result{label: label, set: found, err: err}
		}(src.label, src.fn)
	}
	go func() { wg.Wait(); close(ch) }()

	added := 0
	ok := 0
	for r := range ch {
		if r.err != nil || r.set == nil {
			p.optionalWarning(r.label + ": source unavailable")
			continue
		}
		n := into.Merge(p.allowed(r.set))
		added += n
		ok++
		p.sourceOK++
	}
	st.OK(fmt.Sprintf("%d sources, %d new names", ok, added))
	p.con.SetStat("names", into.Len())
}

// absorb folds a tool's output file into the candidate set, tolerating its absence:
// a tool that failed has already reported so through its step line, and losing the
// other four sources because one of them did not run is not a trade worth making.
func (p *Pipeline) absorb(into *Set, path string) {
	f, err := os.Open(path)
	if err != nil {
		p.con.Warn(fmt.Sprintf("could not read %s: %v", filepath.Base(path), err))
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		n := Normalise(sc.Text())
		if InScope(n, p.opt.Target) && !p.excluded(n) {
			into.Add(n)
		}
	}
	if err := sc.Err(); err != nil {
		p.optionalWarning(filepath.Base(path) + ": " + err.Error())
	}
}

// fromAPI runs one in-process source inside a console step, so an HTTP query looks
// the same on screen as an external tool and takes the same amount of explaining.
func (p *Pipeline) fromAPI(ctx context.Context, into *Set, label string,
	fn func(context.Context, string) (*Set, error)) {

	if p.opt.DryRun {
		p.con.Start(label).Skipped("dry run")
		return
	}
	st := p.con.Start(label)
	found, err := fn(ctx, p.opt.Target)
	if err != nil {
		// A passive source being unreachable is routine — crt.sh rate limits, the
		// archive times out — and is not a reason to fail the phase.
		st.Failed(err.Error())
		p.optionalWarning(label + ": " + err.Error())
		return
	}
	into.Merge(p.allowed(found))
	p.sourceOK++
	st.OK(fmt.Sprintf("%d names", found.Len()))
}

// ---------------------------------------------------------------------------
// Phase 2 — brute force
// ---------------------------------------------------------------------------

func (p *Pipeline) phaseBrute(ctx context.Context) error {
	art := p.L.Path("02_brute.txt")
	p.con.Detail("wordlist", filepath.Base(p.wl.Brute))
	p.con.Detail("entries", CountLines(p.wl.Brute))

	if !p.need("puredns", "brute force") {
		return p.empty(art)
	}
	if !fileHasContent(p.wl.Brute) {
		p.con.Warn("The wordlist is empty or missing, so there is nothing to try")
		return p.empty(art)
	}

	out := p.L.Temp("brute.txt")
	// No --skip-wildcard-filter here, unlike phase 1. A brute force against a
	// wildcard zone returns the entire wordlist as "resolved", and letting that
	// through poisons every phase downstream with tens of thousands of names that
	// were never configured.
	p.exec(ctx, "Brute forcing subdomains", "brute", "",
		"puredns", "bruteforce", p.wl.Brute, p.opt.Target,
		"-r", p.wl.Resolvers, "-w", out,
		"--rate-limit", itoa(p.prof.DNSRate))

	n, err := p.save(art, out)
	if err != nil {
		return err
	}
	p.con.Detail("resolved", n)
	p.con.SetStat("resolved", n)
	return nil
}

// ---------------------------------------------------------------------------
// Phase 3 — recursive brute force
//
// Brute forces a shorter wordlist against each host already found, which is what
// finds the third and fourth level names (api.internal.example.com) that a
// single-level brute force cannot reach.
//
// The fan-out is a worker pool here. The shell version wrote a worker script to disk
// and drove it with xargs -P, which worked but meant every parent hostname passed
// through a second process boundary; a Go worker takes the name as a string and hands
// it to execve as one argument.
// ---------------------------------------------------------------------------

func (p *Pipeline) phaseRecursive(ctx context.Context) error {
	art := p.L.Path("03_recursive.txt")

	seeds, err := p.seeds()
	if err != nil {
		return err
	}
	parents := recursionParents(seeds, maxRecursionParents)
	p.con.Detail("parents", len(parents))
	p.con.Detail("workers", p.prof.Fanout)
	p.con.Detail("DNS rate", fmt.Sprintf("%d/s total, %d/s per worker",
		p.prof.DNSRate, p.prof.DNSRatePerWorker()))

	if len(parents) == 0 || !p.need("puredns", "recursion") {
		return p.empty(art)
	}

	words := p.L.Temp("rec_words.txt")
	n, err := HeadLines(p.wl.Brute, words, p.prof.RecWords)
	if err != nil {
		return err
	}
	p.con.Detail("words per parent", n)
	if n == 0 {
		p.con.Warn("No wordlist available for recursion")
		return p.empty(art)
	}

	outDir := p.L.Temp("rec")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := p.recurse(ctx, parents, words, outDir); err != nil {
		return err
	}

	found, err := p.mergeDir(outDir)
	if err != nil {
		return err
	}
	if err := found.WriteFile(art); err != nil {
		return err
	}
	p.con.Detail("hosts found", found.Len())
	p.con.SetStat("resolved", found.Len())
	return nil
}

// maxRecursionParents caps the fan-out. Recursing into every host found on a large
// target is a multiplication, not an addition: 20,000 parents at 5,000 words each is
// a hundred million queries, which is a week of scanning and a complaint from the
// resolver operator.
const maxRecursionParents = 2000

// recursionParents picks the hosts worth recursing into: ones that already have a
// subdomain label and are not so deep that another level is implausible. Sorted order
// comes from the set, so the same seeds always produce the same parent list and a
// resumed run recurses into the same hosts.
func recursionParents(seeds *Set, limit int) []string {
	var out []string
	for _, name := range seeds.Sorted() {
		labels := strings.Count(name, ".") + 1
		if labels < 3 || labels > 5 {
			continue
		}
		out = append(out, name)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// recurse runs one puredns per parent across Fanout workers, reporting progress
// against a real total rather than an indefinite spinner — this is the phase that
// takes longest, so it is the one where "how far along is it?" matters most.
//
// Each worker's output goes to its own file and its log to its own file under
// logs/recursive/, so two thousand parents do not produce two thousand entries in the
// main log directory and a failing parent can still be traced.
func (p *Pipeline) recurse(ctx context.Context, parents []string, words, outDir string) error {
	child := &Runner{
		LogDir:   filepath.Join(p.L.Logs, "recursive"),
		DryRun:   p.opt.DryRun,
		Env:      p.run.Env,
		OnResult: p.recordResult,
	}
	rate := itoa(p.prof.DNSRatePerWorker())
	workers := p.prof.Fanout
	if workers < 1 {
		workers = 1
	}

	sem := make(chan struct{}, workers)
	finished := make(chan struct{}, len(parents))
	var wg sync.WaitGroup

	for _, parent := range parents {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			defer func() { finished <- struct{}{} }()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			out := filepath.Join(outDir, safeName(name)+".txt")
			child.Run(ctx, name, "",
				"puredns", "bruteforce", words, name,
				"-r", p.wl.Resolvers, "-w", out, "--rate-limit", rate)
		}(parent)
	}
	go func() { wg.Wait(); close(finished) }()

	done := 0
	for range finished {
		done++
		p.con.Progress("parents", done, len(parents))
	}
	return ctx.Err()
}

// mergeDir folds every file in a directory into one in-scope set. Used by the
// recursive phase, whose output arrives as one file per worker.
func (p *Pipeline) mergeDir(dir string) (*Set, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return NewSet(), nil
		}
		return nil, err
	}
	out := NewSet()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		s, err := LoadSet(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out.Merge(s)
	}
	return out.InScope(p.opt.Target), nil
}

// ---------------------------------------------------------------------------
// Phase 4 — permutations
//
// Takes the hosts already found and mutates them — dev1 becomes dev2, api-staging
// becomes api-prod — then resolves the result. It finds the neighbours of what you
// already have, which is where the interesting hosts usually are.
// ---------------------------------------------------------------------------

func (p *Pipeline) phasePermute(ctx context.Context) error {
	art := p.L.Path("04_perms.txt")

	seeds, err := p.seeds()
	if err != nil {
		return err
	}
	p.con.Detail("seeds available", seeds.Len())
	p.con.Detail("seed cap", p.prof.PermSeeds)

	if seeds.Len() == 0 || !p.need("gotator", "permutations") {
		return p.empty(art)
	}
	if !fileHasContent(p.wl.Perms) {
		p.con.Warn("No permutation wordlist available")
		return p.empty(art)
	}

	all := p.L.Temp("perm_seeds_all.txt")
	if err := seeds.WriteFile(all); err != nil {
		return err
	}
	seedFile := p.L.Temp("perm_seeds.txt")
	used, err := HeadLines(all, seedFile, p.prof.PermSeeds)
	if err != nil {
		return err
	}
	p.con.Detail("seeds used", used)

	// depth 1 and numbers 3 are deliberate: depth 2 multiplies the output by the
	// wordlist again, and the resolution pass — not the generation — is the expensive
	// half of this phase.
	raw := p.L.Temp("perms_raw.txt")
	bctx, cancel := budget(ctx, 30*time.Minute)
	p.exec(bctx, "Generating permutations", "gotator", raw,
		"gotator", "-sub", seedFile, "-perm", p.wl.Perms,
		"-depth", "1", "-numbers", "3", "-silent")
	cancel()

	if !fileHasContent(raw) {
		p.con.Warn("The permutation generator produced nothing")
		return p.empty(art)
	}
	p.con.Detail("permutations generated", CountLines(raw))

	if !p.need("puredns", "permutation resolution") {
		// Unresolved permutations are not a result. They are a wordlist, and one that
		// is mostly wrong by construction — writing millions of invented names into
		// an artifact that feeds the HTTP phase would be worse than writing nothing.
		return p.empty(art)
	}

	out := p.L.Temp("perms_resolved.txt")
	p.exec(ctx, "Resolving permutations", "resolve_perms", "",
		"puredns", "resolve", raw,
		"-r", p.wl.Resolvers, "-w", out,
		"--rate-limit", itoa(p.prof.DNSRate))

	n, err := p.save(art, out)
	if err != nil {
		return err
	}
	p.con.Detail("resolved", n)
	p.con.SetStat("resolved", n)
	return nil
}

// ---------------------------------------------------------------------------
// Phase 5 — HTTP probing
//
// One httpx pass writes JSONL, and the URL list is derived from it. The original ran
// httpx twice, once for URLs and again for metadata, which doubled the traffic against
// the client's infrastructure to produce data it already had.
// ---------------------------------------------------------------------------

func (p *Pipeline) phaseHTTP(ctx context.Context) error {
	jsonl := p.L.Path("05_http.jsonl")
	urls := p.L.Path("05_live_urls.txt")

	master, err := p.rebuildMaster()
	if err != nil {
		return err
	}
	p.con.Detail("names to probe", master.Len())
	p.con.Detail("threads", p.prof.HTTPXThreads)

	if master.Len() == 0 || !p.need("httpx", "HTTP probing") {
		return p.empty(jsonl, urls)
	}

	p.exec(ctx, "Probing HTTP services", "httpx", "",
		"httpx", "-l", p.L.Master(), "-json", "-o", jsonl,
		"-threads", itoa(p.prof.HTTPXThreads),
		"-timeout", "8", "-retries", "1",
		"-follow-redirects", "-tech-detect", "-title", "-status-code",
		"-silent", "-no-color")

	found, err := URLsFromJSONL(jsonl)
	if err != nil {
		return err
	}
	if err := WriteLines(urls, KeepHTTP(found)); err != nil {
		return err
	}
	p.con.Detail("live services", CountLines(urls))
	p.con.SetStat("live", CountLines(urls))

	// TLS SAN/CN names are often internal vhosts that DNS never listed.
	p.tlsNames(ctx)
	return nil
}

func (p *Pipeline) tlsNames(ctx context.Context) {
	if !p.need("tlsx", "TLS certificate names") {
		return
	}
	out := p.L.Temp("tlsx.txt")
	p.execOptional(ctx, "Reading TLS SAN/CN names", "tlsx", out,
		"tlsx", "-l", p.L.Master(), "-san", "-cn", "-silent")
	s, err := LoadSet(out)
	if err != nil || s.Len() == 0 {
		return
	}
	s = p.allowed(s)
	art := p.L.Path("05_tls_hosts.txt")
	_ = s.WriteFile(art)
	p.con.Detail("tls names", s.Len())
}

// ---------------------------------------------------------------------------
// Phase 6 — port scanning
//
// Two corrections over the original. The scan type is chosen from privilege, because
// naabu defaults to SYN, SYN needs raw sockets, and as an unprivileged user it aborted
// with a permission error that the original discarded into /dev/null — the phase
// "succeeded" with no ports every single time. And services found on other ports are
// probed and folded into the live URL set, so an admin panel on :8443 is actually
// looked at instead of being listed once and forgotten.
// ---------------------------------------------------------------------------

func (p *Pipeline) phasePorts(ctx context.Context) error {
	art := p.L.Path("06_ports.txt")
	extra := p.L.Path("06_extra_urls.txt")

	master, err := p.rebuildMaster()
	if err != nil {
		return err
	}
	mode := "connect"
	if os.Geteuid() == 0 {
		mode = "syn"
	}
	p.con.Detail("hosts", master.Len())
	p.con.Detail("scan type", fmt.Sprintf("%s at %d/s", mode, p.prof.NaabuRate))

	if master.Len() == 0 || !p.need("naabu", "port scanning") {
		return p.empty(art, extra)
	}
	if mode == "connect" {
		p.con.Info("Not running as root, so this is a connect scan: slower, but it needs no privileges.")
	}

	p.exec(ctx, "Scanning ports", "naabu", "",
		"naabu", "-list", p.L.Master(), "-top-ports", "1000", "-o", art,
		"-rate", itoa(p.prof.NaabuRate), "-c", "50", "-scan-type", mode,
		"-silent", "-no-color", "-stats=false")
	p.con.Detail("open ports", CountLines(art))

	return p.probeExtraPorts(ctx, art, extra)
}

// probeExtraPorts runs httpx over everything that is not :80 or :443, which phase 6
// has already covered. Without this step the port scan is a list of numbers nobody
// follows up.
func (p *Pipeline) probeExtraPorts(ctx context.Context, ports, out string) error {
	lines, err := LoadLines(ports)
	if err != nil {
		return err
	}
	var candidates []string
	for _, l := range lines {
		if _, port := HostPort(l); port != "80" && port != "443" {
			candidates = append(candidates, l)
		}
	}
	if len(candidates) == 0 || !p.need("httpx", "probing non-standard ports") {
		return p.empty(out)
	}

	cand := p.L.Temp("extra_ports.txt")
	if err := WriteLines(cand, candidates); err != nil {
		return err
	}
	work := p.L.Temp("extra_urls.txt")
	p.exec(ctx, fmt.Sprintf("Probing %d non-standard ports", len(candidates)), "httpx_ports", "",
		"httpx", "-l", cand, "-o", work,
		"-threads", itoa(p.prof.HTTPXThreads),
		"-timeout", "8", "-retries", "1", "-silent", "-no-color")

	found, err := LoadLines(work)
	if err != nil {
		return err
	}
	if err := WriteLines(out, KeepHTTP(found)); err != nil {
		return err
	}
	p.con.Detail("extra services", CountLines(out))
	return nil
}

// ---------------------------------------------------------------------------
// Phase 7 — crawling
//
// Crawls the live services and mines the archive for URLs, then folds the hostnames
// back into the DNS results. A name that appears only inside a JavaScript bundle, a
// CSP header or a redirect chain is invisible to every technique in phases 1 to 4,
// and this is the phase that catches it.
// ---------------------------------------------------------------------------

func (p *Pipeline) phaseCrawl(ctx context.Context) error {
	urlArt := p.L.Path("07_urls.txt")
	hostArt := p.L.Path("07_crawled_hosts.txt")

	liveFile, live, err := p.liveTargets()
	if err != nil {
		return err
	}
	p.con.Detail("live services", len(live))
	p.con.Detail("crawl concurrency", p.prof.KatanaConc)

	if len(live) == 0 {
		p.con.Warn("No live services were found, so there is nothing to crawl")
	}

	urls, crawlErr := p.crawlURLs(ctx, liveFile)
	urls = p.collectedURLs(urls)
	previous, err := LoadLines(urlArt)
	if err != nil {
		return err
	}
	urls = p.collectedURLs(append(urls, previous...))
	if err := WriteLines(urlArt, urls); err != nil {
		return err
	}
	p.con.Detail("URLs collected", len(urls))

	return errors.Join(crawlErr, p.crawledHosts(ctx, urls, hostArt))
}

// execOn is exec on a runner other than the shared one, for the two commands that
// need a setting the shared runner must not keep: waybackurls takes its target on
// standard input, and gowitness writes its database into the working directory. The
// step line is identical either way.
func (p *Pipeline) execOn(ctx context.Context, r *Runner,
	label, logName, outPath string, cmd ...string) Result {

	return p.report(p.con.Start(label), r.Run(ctx, logName, outPath, cmd...))
}

// derive builds such a runner, inheriting the log directory, environment and dry-run
// flag so none of those can drift from the shared one.
func (p *Pipeline) derive() *Runner {
	return &Runner{LogDir: p.L.Logs, DryRun: p.opt.DryRun, Env: p.run.Env, OnResult: p.recordResult}
}

// lines reads a tool's output file, treating an unreadable one as empty: the step line
// has already carried the failure, and losing the other source because this one broke
// is not a trade worth making.
func (p *Pipeline) lines(path string) []string {
	l, err := LoadLines(path)
	if err != nil {
		p.con.Warn(fmt.Sprintf("could not read %s: %v", filepath.Base(path), err))
		return nil
	}
	return l
}

// crawledHosts writes 07_crawled_hosts.txt, this phase's contribution to the master
// list.
//
// The artifact is (names already in master) ∪ (names newly resolved), and it has to
// stay that way. The original wrote only the names that were new relative to the
// merged master, which is correct exactly once: on a re-run or a resume those names
// were already in master, so the difference was empty, the artifact was truncated to
// nothing, and since the master list is rebuilt by merging artifacts rather than
// remembering anything, every host this phase had ever found vanished from the final
// results. TestArtifactIsKnownPlusNew is there to stop that returning.
func (p *Pipeline) crawledHosts(ctx context.Context, urls []string, art string) error {
	hosts := p.allowed(HostsOf(urls, p.opt.Target))
	previous, err := LoadSet(p.L.Path("07_candidates.txt"))
	if err != nil {
		return err
	}
	hosts.Merge(p.allowed(previous))
	p.con.Detail("hostnames in URLs", hosts.Len())
	if hosts.Len() == 0 {
		return p.empty(art)
	}

	master, err := LoadSet(p.L.Master())
	if err != nil {
		return err
	}
	known := hosts.Intersect(master)
	unknown := hosts.Minus(master)
	p.con.Detail("already known", known.Len())
	p.con.Detail("new to verify", unknown.Len())

	// Only the new names are resolved — re-resolving thousands of hosts that phases 1
	// to 4 already confirmed is pure cost — but the known ones are still written out,
	// because the artifact has to describe everything this phase found, not the delta.
	out, err := LoadSet(art)
	if err != nil {
		return err
	}
	out = p.allowed(out)
	out.Merge(known)
	if hosts.Len() > 0 {
		verified, err := p.resolveNames(ctx, hosts)
		if err != nil {
			if verified != nil {
				out.Merge(verified)
				err = errors.Join(err, out.WriteFile(art))
			}
			return err
		}
		out.Merge(verified)
	}
	if err := p.allowed(out).WriteFile(art); err != nil {
		return err
	}
	p.con.Detail("hosts contributed", CountLines(art))
	return p.deepen(ctx)
}

// deepen is the hidden-name pass: take every hostname discovered so far,
// including ones that only appeared inside JS or TLS certs, and brute a short
// wordlist one label deeper. That is how api.internal.staging.example.com
// shows up after you already have internal.staging.example.com.
func (p *Pipeline) deepen(ctx context.Context) error {
	if !p.need("puredns", "sub-subdomain deepening") {
		return nil
	}
	if err := func() error { _, err := p.rebuildMaster(); return err }(); err != nil {
		return err
	}
	seeds, err := p.rebuildMaster()
	if err != nil {
		return err
	}
	parents := recursionParents(seeds, 800)
	if len(parents) == 0 {
		return nil
	}
	p.con.Detail("deepen parents", len(parents))
	words := p.L.Temp("deep_words.txt")
	n, err := HeadLines(p.wl.Brute, words, min(p.prof.RecWords, 2000))
	if err != nil || n == 0 {
		return err
	}
	outDir := p.L.Temp("deep")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := p.recurse(ctx, parents, words, outDir); err != nil {
		return err
	}
	found, err := p.mergeDir(outDir)
	if err != nil {
		return err
	}
	art := p.L.Path("07_deep_hosts.txt")
	if err := found.WriteFile(art); err != nil {
		return err
	}
	p.con.Detail("deep hosts", found.Len())
	p.con.SetStat("resolved", found.Len())
	return nil
}

// resolveNames shares the durable candidate recovery path with passive intel.
func (p *Pipeline) resolveNames(ctx context.Context, names *Set) (*Set, error) {
	return p.resolveCandidates(ctx, names, "crawled")
}

// ---------------------------------------------------------------------------
// Phase 8 — vulnerability scan
//
// Standard runs stop at medium. Info and low findings across a large attack surface
// number in the thousands — every missing security header on every host — and two
// criticals buried in that is how a real finding goes unread. --deep asks for them
// explicitly.
//
// Both output formats are written from the one pass: the text file is what an operator
// reads, the JSONL is what the report and any downstream tooling parse.
// ---------------------------------------------------------------------------

func (p *Pipeline) phaseVulns(ctx context.Context) error {
	txt := p.L.Report("nuclei.txt")
	jsonl := p.L.Report("nuclei.jsonl")

	liveFile, live, err := p.liveTargets()
	if err != nil {
		return err
	}
	sev := "medium,high,critical"
	if p.opt.Deep {
		sev = "info,low,medium,high,critical"
	}
	p.con.Detail("targets", len(live))
	p.con.Detail("severities", sev)

	if len(live) == 0 || !p.need("nuclei", "vulnerability scanning") {
		return p.empty(txt, jsonl)
	}

	p.exec(ctx, "Scanning for vulnerabilities", "nuclei", "", p.nucleiCommand(liveFile)...)

	n := CountLines(txt)
	p.con.Detail("findings", n)
	if n > 0 {
		for _, s := range severities {
			if c := countSeverity(txt, s); c > 0 {
				p.con.Detail(s, c)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Phase 9 — screenshots
//
// gowitness drives a real Chromium, so the browser is located before anything runs and
// the phase explains what to install when there is none. The original assumed a Linux
// binary name on PATH, so on macOS this phase failed every single time and the error
// went to /dev/null.
// ---------------------------------------------------------------------------

func (p *Pipeline) phaseScreenshots(ctx context.Context) error {
	shots := p.L.Report("screenshots")

	liveFile, live, err := p.liveTargets()
	if err != nil {
		return err
	}
	p.con.Detail("live services", len(live))

	// Nothing here produces an artifact other phases read, so there is no empty file
	// to write: a skipped screenshot phase changes nothing downstream.
	if len(live) == 0 || !p.need("gowitness", "screenshots") {
		return nil
	}
	chrome := host.FindChrome()
	if chrome == "" {
		p.con.Warn("No Chromium or Chrome was found, so screenshots are skipped")
		p.con.Info("Install one with: " + chromeHint(p.h.OS))
		return nil
	}
	p.con.Detail("browser", filepath.Base(chrome))

	if err := os.MkdirAll(shots, 0o755); err != nil {
		return err
	}
	shotList := p.L.Temp("shot_urls.txt")
	// Capped deliberately. Five thousand screenshots is hours of browser startup for
	// very little extra signal, and it was the most common reason a scan never ended.
	n, err := HeadLines(liveFile, shotList, maxScreenshots)
	if err != nil {
		return err
	}
	if n < len(live) {
		p.con.Info(fmt.Sprintf("Capping at %d of %d services.", n, len(live)))
	}

	// gowitness writes its database relative to the working directory, so the runner
	// is given one rather than the run being left to litter wherever it started.
	r := p.derive()
	r.Dir = shots
	bctx, cancel := budget(ctx, 30*time.Minute)
	p.execOn(bctx, r, fmt.Sprintf("Capturing %d screenshots", n), "gowitness", "",
		"gowitness", "scan", "file", "-f", shotList,
		"--chrome-path", chrome, "--screenshot-path", shots,
		"--write-db", "--timeout", "15")
	cancel()

	p.con.Detail("screenshots", countFiles(shots, ".png"))
	return nil
}

const maxScreenshots = 500

func chromeHint(goos string) string {
	if goos == "darwin" {
		return "brew install --cask chromium"
	}
	return "apt install chromium  (or your distribution's equivalent)"
}

// countFiles counts files with a given extension, one level deep. Reported rather than
// trusted from the tool's exit status, because gowitness exits zero after failing to
// reach every single target.
func countFiles(dir, ext string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ext) {
			n++
		}
	}
	return n
}
