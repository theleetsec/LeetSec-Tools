package scan

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/theleetsec/LeetSec-Tools/internal/ui"
)

func hardeningPipeline(t *testing.T) *Pipeline {
	t.Helper()
	root := t.TempDir()
	fixture, err := filepath.Abs("../../tests/fixtures/fake-tool.sh")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"amass", "subfinder", "puredns", "dnsx", "katana", "waybackurls", "gau"} {
		if err := os.Symlink(fixture, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	t.Setenv("NO_COLOR", "1")
	con, err := ui.New(&bytes.Buffer{}, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { con.Close() })
	l := &Layout{Run: filepath.Join(root, "run"), Work: filepath.Join(root, "scratch"), Logs: filepath.Join(root, "run/logs")}
	for _, dir := range []string{l.Run, l.Work, l.Logs} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	st, err := OpenState(l.Run, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	p := &Pipeline{opt: Options{Target: "example.com"}, L: l, st: st, con: con, prof: Profile{DNSRate: 5000, KatanaConc: 2}}
	p.run = &Runner{LogDir: l.Logs, OnResult: p.recordResult}
	t.Setenv("FAKE_TOOL_TRACE", filepath.Join(root, "commands.txt"))
	return p
}

func TestAmassDatabaseExportAndOptionalFailure(t *testing.T) {
	for _, mode := range []string{"success", "enum_failure", "export_failure", "absent"} {
		t.Run(mode, func(t *testing.T) {
			p := hardeningPipeline(t)
			if mode == "enum_failure" {
				t.Setenv("FAKE_AMASS_FAIL", "1")
			}
			if mode == "export_failure" {
				t.Setenv("FAKE_AMASS_EXPORT_FAIL", "1")
			}
			if mode == "absent" {
				if err := os.Remove(filepath.Join(strings.Split(os.Getenv("PATH"), ":")[0], "amass")); err != nil {
					t.Fatal(err)
				}
			}
			var found *Set
			err := p.runPhase(context.Background(), phase{id: "p1", fn: func(p *Pipeline, ctx context.Context) error {
				found = NewSet()
				p.amass(ctx, found)
				out := p.L.Temp("other.txt")
				p.execOptional(ctx, "other passive source", "subfinder", "", "subfinder", "-d", p.opt.Target, "-o", out)
				p.absorb(found, out)
				return p.resolveInto(ctx, p.L.Path("01_passive.txt"), found, "passive")
			}})
			if err != nil {
				t.Fatalf("optional %s invalidated phase: %v", mode, err)
			}
			if !found.Has("api.example.com") {
				t.Fatal("lost successful alternate source")
			}
			if mode == "success" && !found.Has("vpn.example.com") {
				t.Fatal("did not read subs export")
			}
			if mode != "success" && CountLines(p.L.Path("optional-warnings.log")) == 0 {
				t.Fatal("degradation was silent")
			}
			for _, cmd := range p.run.Executed() {
				if strings.Contains(cmd, "amass enum") && strings.Contains(cmd, " -o ") {
					t.Fatal("unsupported enum -o")
				}
			}
			trace, _ := os.ReadFile(os.Getenv("FAKE_TOOL_TRACE"))
			if mode == "success" && !strings.Contains(string(trace), "amass subs -names") {
				t.Fatal("missing explicit database export")
			}
		})
	}
}

func TestDNSRecoveryRetainsCandidatesAndRejectsUnresolved(t *testing.T) {
	p := hardeningPipeline(t)
	t.Setenv("FAKE_DNS_DROP", "1")
	in := NewSet()
	in.AddAll([]string{"api.example.com", "bulk-miss.example.com", "aaaa-only.example.com", "_service.example.com", "nx.example.com", "other.invalid"})
	err := p.runPhase(context.Background(), phase{id: "p1", fn: func(p *Pipeline, ctx context.Context) error {
		return p.resolveInto(ctx, p.L.Path("01_passive.txt"), in, "passive")
	}})
	if err != nil {
		t.Fatal(err)
	}
	found, _ := LoadSet(p.L.Path("01_passive.txt"))
	for _, h := range []string{"bulk-miss.example.com", "aaaa-only.example.com", "_service.example.com"} {
		if !found.Has(h) {
			t.Errorf("lost %s", h)
		}
	}
	if found.Has("nx.example.com") || found.Has("other.invalid") {
		t.Fatal("unresolved/out-of-scope name promoted")
	}
	candidates, _ := LoadSet(p.L.Path("01_candidates.txt"))
	missing, _ := LoadSet(p.L.Path("01_unresolved.txt"))
	if candidates.Len() != 5 || missing.Len() != 1 || !missing.Has("nx.example.com") {
		t.Fatalf("candidate reconciliation: %v / %v", candidates.Sorted(), missing.Sorted())
	}
	trace, _ := os.ReadFile(os.Getenv("FAKE_TOOL_TRACE"))
	for _, flag := range []string{"--skip-sanitize", "-a -aaaa", "-rate-limit 500", "-retry 3"} {
		if !strings.Contains(string(trace), flag) {
			t.Errorf("missing %s", flag)
		}
	}
	// A continuation recovers from durable input even when no new source names arrive.
	if _, err := p.resolveCandidates(context.Background(), NewSet(), "passive"); err != nil {
		t.Fatal(err)
	}
	retained, _ := LoadSet(p.L.Path("01_candidates.txt"))
	if retained.Len() != 5 {
		t.Fatal("retry lost saved input")
	}
}

func TestDNSRecoveryFailureKeepsPhasePendingAndPartialOutput(t *testing.T) {
	p := hardeningPipeline(t)
	t.Setenv("FAKE_DNS_DROP", "1")
	t.Setenv("FAKE_DNSX_FAIL", "1")
	in := NewSet()
	in.AddAll([]string{"api.example.com", "bulk-miss.example.com"})
	err := p.runPhase(context.Background(), phase{id: "p1", fn: func(p *Pipeline, ctx context.Context) error {
		return p.resolveInto(ctx, p.L.Path("01_passive.txt"), in, "passive")
	}})
	if err == nil {
		t.Fatal("required DNS failure checkpointed as success")
	}
	partial, _ := LoadSet(p.L.Path("01_passive.txt"))
	if !partial.Has("api.example.com") {
		t.Fatal("lost partial resolved output")
	}
	if p.st.IsDone("p1") {
		t.Fatal("failed phase marked done")
	}
}

func TestCollectionExclusionsAtEveryIngress(t *testing.T) {
	p := hardeningPipeline(t)
	file := filepath.Join(t.TempDir(), "exclude.txt")
	if err := os.WriteFile(file, []byte("# collection only\n*.MX.SAAS.EXAMPLE.COM\nexact.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var err error
	p.exclusions, err = ReadExclusions(file)
	if err != nil {
		t.Fatal(err)
	}
	in := NewSet()
	in.AddAll([]string{"customer.mx.saas.example.com", "deep.customer.mx.saas.example.com", "mx.saas.example.com", "mail.other.example.com", "exact.example.com", "notmx.saas.example.com"})
	allowed := p.allowed(in)
	if allowed.Len() != 3 || !allowed.Has("mx.saas.example.com") || !allowed.Has("mail.other.example.com") || !allowed.Has("notmx.saas.example.com") {
		t.Fatal(allowed.Sorted())
	}
	if err := in.WriteFile(p.L.Path("05_tls_hosts.txt")); err != nil {
		t.Fatal(err)
	}
	m, err := p.rebuildMaster()
	if err != nil || m.Len() != 3 {
		t.Fatalf("master gate: %v %v", m, err)
	}
	urls := p.collectedURLs([]string{"https://user@CUSTOMER.mx.saas.example.com:443/reintroduced", "https://mx.saas.example.com/path"})
	if len(urls) != 1 {
		t.Fatal("archive reintroduced excluded host", urls)
	}
	if err := p.bindExclusions(); err != nil {
		t.Fatal(err)
	}
	p.L.Resumed = true
	p.exclusions = nil
	if err := p.bindExclusions(); err == nil {
		t.Fatal("resume silently changed filters")
	}
	for _, bad := range []string{"*example.com", "example.com;touch", "*.bad..example.com", "example.com."} {
		os.WriteFile(file, []byte(bad), 0o644)
		if _, err := ReadExclusions(file); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCrawlBudgetAndContinuation(t *testing.T) {
	p := hardeningPipeline(t)
	var seeds []string
	for i := 0; i < 201; i++ {
		seeds = append(seeds, "https://seed"+strconv.Itoa(i)+".example.com")
	}
	in := p.L.Temp("live.txt")
	if err := WriteLines(in, seeds); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_KATANA_STATE_FILE", filepath.Join(t.TempDir(), "calls"))
	t.Setenv("FAKE_KATANA_TIMEOUT_CALL", "2")
	before, err := p.crawlURLs(context.Background(), in)
	if err == nil {
		t.Fatal("truncated crawl appears complete")
	}
	if CountLines(p.L.Path("07_katana_done_urls.txt")) != 100 {
		t.Fatal("unfinished batch was checkpointed")
	}
	if len(before) == 0 {
		t.Fatal("lost partial URLs")
	}
	t.Setenv("FAKE_KATANA_TIMEOUT_CALL", "0")
	p.opt.CrawlBudget = 2 * time.Second
	after, err := p.crawlURLs(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if CountLines(p.L.Path("07_katana_done_urls.txt")) != 201 || len(after) < len(before) {
		t.Fatal("continuation lost progress/output")
	}
	trace, _ := os.ReadFile(os.Getenv("FAKE_TOOL_TRACE"))
	if strings.Count(string(trace), "katana ") != 4 || strings.Count(string(trace), "waybackurls") != 1 || strings.Count(string(trace), "gau ") != 1 {
		t.Fatal("replayed completed work", string(trace))
	}
	if crawlBudget(1) != 45*time.Minute || crawlBudget(1001) != 90*time.Minute || crawlBudget(50000) != 6*time.Hour {
		t.Fatal("incorrect scaling")
	}
	for _, good := range []string{"1", "45m", "2h", "604800s"} {
		if _, err := ParseCrawlBudget(good); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{"0", "-1", "1.5h", "1h30m", "169h", "999999999999999999999999h"} {
		if _, err := ParseCrawlBudget(bad); err == nil {
			t.Errorf("accepted budget %q", bad)
		}
	}
}

func TestArchiveBudgetTruncationCanBeContinued(t *testing.T) {
	p := hardeningPipeline(t)
	in := p.L.Temp("live.txt")
	if err := WriteLines(in, []string{"https://www.example.com"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_WAYBACK_TIMEOUT", "1")
	urls, err := p.crawlURLs(context.Background(), in)
	if err == nil || len(urls) == 0 {
		t.Fatal("archive truncation not retained/reported")
	}
	if _, err := os.Stat(p.L.Path("07_wayback_complete")); !os.IsNotExist(err) {
		t.Fatal("truncated archive checkpointed")
	}
	t.Setenv("FAKE_WAYBACK_TIMEOUT", "0")
	p.opt.CrawlBudget = time.Second
	if _, err := p.crawlURLs(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	trace, _ := os.ReadFile(os.Getenv("FAKE_TOOL_TRACE"))
	if strings.Count(string(trace), "katana ") != 1 || strings.Count(string(trace), "gau ") != 1 || strings.Count(string(trace), "waybackurls") != 2 {
		t.Fatal("continuation replayed completed sources", string(trace))
	}
}

func TestBashGoHardeningParity(t *testing.T) {
	p := hardeningPipeline(t)
	t.Setenv("FAKE_DNS_DROP", "1")
	p.exclusions = []string{"*.mx.saas.example.com"}
	input := NewSet()
	input.AddAll([]string{"api.example.com", "bulk-miss.example.com", "aaaa-only.example.com", "_service.example.com", "nx.example.com", "customer.mx.saas.example.com", "mx.saas.example.com", "other.invalid"})
	if err := p.resolveInto(context.Background(), p.L.Path("01_passive.txt"), input, "passive"); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	shellRoot := t.TempDir()
	unfiltered := filepath.Join(shellRoot, "input.txt")
	if err := input.WriteFile(unfiltered); err != nil {
		t.Fatal(err)
	}
	code := `
set -uo pipefail
. "$1/lib/compat.sh"; . "$1/lib/ui.sh"; . "$1/lib/pipeline.sh"; . "$1/lib/hardening.sh"
compat_init; ui_init
OUT_DIR="$2/run"; WORK_DIR="$2/work"; LOG_DIR="$2/run/logs"
mkdir -p "$OUT_DIR" "$WORK_DIR" "$LOG_DIR"
DNS_RATE=5000; WL_RESOLVERS="$2/resolvers.txt"
printf '*.mx.saas.example.com\n' > "$OUT_DIR/collection-exclusions.txt"
pipe_collection_names example.com < "$3" | compat_sort -u > "$OUT_DIR/01_candidates.txt"
pipe_resolve_candidates example.com "$OUT_DIR/01_candidates.txt" "$OUT_DIR/01_passive.txt" 01 passive
`
	cmd := exec.Command("/bin/bash", "-c", code, "parity", root, shellRoot, unfiltered)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shell parity: %v\n%s", err, out)
	}
	for _, filename := range []string{"01_candidates.txt", "01_unresolved.txt", "01_passive.txt"} {
		goBytes, err := os.ReadFile(p.L.Path(filename))
		if err != nil {
			t.Fatal(err)
		}
		shBytes, err := os.ReadFile(filepath.Join(shellRoot, "run", filename))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(goBytes, shBytes) {
			t.Fatalf("%s differs:\nGo %s\nBash %s", filename, goBytes, shBytes)
		}
	}
	var seeds []string
	for i := 0; i < 201; i++ {
		seeds = append(seeds, "https://seed"+strconv.Itoa(i)+".example.com")
	}
	seedFile := filepath.Join(shellRoot, "seeds.txt")
	if err := WriteLines(seedFile, seeds); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_KATANA_STATE_FILE", filepath.Join(t.TempDir(), "calls"))
	t.Setenv("FAKE_KATANA_TIMEOUT_CALL", "2")
	if _, err := p.crawlURLs(context.Background(), seedFile); err == nil {
		t.Fatal("expected truncated Go crawl")
	}
	t.Setenv("FAKE_KATANA_TIMEOUT_CALL", "0")
	if _, err := p.crawlURLs(context.Background(), seedFile); err != nil {
		t.Fatal(err)
	}
	code = `
set -uo pipefail
. "$1/lib/compat.sh"; . "$1/lib/ui.sh"; . "$1/lib/pipeline.sh"; . "$1/lib/hardening.sh"
compat_init; ui_init
OUT_DIR="$2/crawl"; WORK_DIR="$2/work"; LOG_DIR="$2/crawl/logs"
mkdir -p "$OUT_DIR" "$WORK_DIR" "$LOG_DIR"
PIPE_ARG_CRAWL_BUDGET=2h; KATANA_CONC=2; PIPE_TARGET=example.com
export PIPE_TARGET
export FAKE_KATANA_STATE_FILE="$2/shell-calls" FAKE_KATANA_TIMEOUT_CALL=2
rc=0; pipe_crawl_urls "$3" || rc=$?
[ "$rc" -eq 124 ] || exit 3
[ "$(compat_count "$OUT_DIR/07_katana_done_urls.txt")" -eq 100 ] || exit 4
export FAKE_KATANA_TIMEOUT_CALL=0
pipe_crawl_urls "$3"
`
	cmd = exec.Command("/bin/bash", "-c", code, "parity", root, shellRoot, seedFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("crawl parity: %v\n%s", err, out)
	}
	for _, filename := range []string{"07_katana_done_urls.txt", "07_katana_urls.txt", "07_wayback_urls.txt", "07_gau_urls.txt", "07_crawl_pending.txt"} {
		goBytes, err := os.ReadFile(p.L.Path(filename))
		if err != nil {
			t.Fatal(err)
		}
		shBytes, err := os.ReadFile(filepath.Join(shellRoot, "crawl", filename))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(goBytes, shBytes) {
			t.Fatalf("crawl %s differs between implementations", filename)
		}
	}
}

func TestRequestedCompletionKeepsSelectedRunResumable(t *testing.T) {
	p := hardeningPipeline(t)
	p.only = idSet([]string{"p1", "p5", "p7"})
	for _, id := range []string{"p1", "p5", "p7"} {
		if err := p.st.MarkDone(id); err != nil {
			t.Fatal(err)
		}
	}
	if !p.requestedSatisfied() {
		t.Fatal("finished selection appears incomplete")
	}
	if p.allSatisfied() {
		t.Fatal("selected run became a full baseline")
	}
	var output bytes.Buffer
	con, err := ui.New(&output, "")
	if err != nil {
		t.Fatal(err)
	}
	defer con.Close()
	p.con = con
	p.reportTerminal(counts{})
	if !strings.Contains(output.String(), "Scan complete: example.com") {
		t.Fatal(output.String())
	}
	if err := p.st.Clear("p7"); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	p.reportTerminal(counts{})
	if !strings.Contains(output.String(), "Scan incomplete: example.com") {
		t.Fatal(output.String())
	}
	if p.requestedSatisfied() {
		t.Fatal("unfinished selection appears complete")
	}
}
