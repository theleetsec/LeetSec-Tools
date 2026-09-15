package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/theleetsec/LeetSec-Tools/internal/host"
)

// dryPlan renders the graph without opening state, creating artifacts, checking
// tool availability or downloading assets. Data-dependent arguments are explicit
// placeholders because discovery has not run.
func (p *Pipeline) dryPlan(ctx context.Context) error {
	if p.opt.Wordlist != "" && !fileHasContent(p.opt.Wordlist) {
		return fmt.Errorf("wordlist %s is missing or empty", p.opt.Wordlist)
	}
	cache := filepath.Join(host.CacheDir(), "wordlists")
	p.wl = Wordlists{Dir: cache, Brute: filepath.Join(cache, "dns-brute.txt"),
		Perms: filepath.Join(cache, "permutations.txt"), Resolvers: filepath.Join(cache, "resolvers.txt")}
	if p.opt.Wordlist != "" {
		p.wl.Brute = p.opt.Wordlist
	}
	if override := os.Getenv("LEETENUM_PERM_WORDLIST"); fileHasContent(override) {
		p.wl.Perms = override
	}
	p.plan()
	p.con.Info("Planned commands only. <run>, <scratch> and <parent> are placeholders; commands depend on discovered inputs.")
	all := phases()
	for i, ph := range all {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !p.wanted(ph.id) {
			continue
		}
		p.con.Phase(i+1, len(all), ph.title)
		if ph.id == "p1" {
			p.con.Info("Query passive HTTP sources, DNS records and nameservers for zone transfers.")
		}
		if ph.id == "p7" {
			p.con.Info("waybackurls and gau receive the target domain on standard input.")
			p.con.Info("Katana uses completed-seed checkpoints, batches of at most 100, and a size-dependent budget (45m to 6h); --crawl-budget overrides it.")
		}
		for _, argv := range p.plannedCommands(ph.id) {
			p.con.Info("$ " + formatCommand(argv))
		}
	}
	return nil
}

// These command templates describe each phase before any data exists. The
// placeholders intentionally avoid inventing discoveries or persisting a fake run.
func (p *Pipeline) plannedCommands(id string) [][]string {
	target, tmp := p.opt.Target, p.L.Temp
	resolve := func(in, out string, candidateList bool) []string {
		cmd := []string{"puredns", "resolve", in, "-r", p.wl.Resolvers, "-w", out,
			"--rate-limit", itoa(p.prof.DNSRate)}
		if candidateList {
			cmd = append(cmd, "--skip-wildcard-filter", "--skip-validation", "--skip-sanitize")
		}
		return cmd
	}
	brute := func(words, parent, out string, rate int) []string {
		return []string{"puredns", "bruteforce", words, parent, "-r", p.wl.Resolvers,
			"-w", out, "--rate-limit", itoa(rate)}
	}
	switch id {
	case "p1":
		return [][]string{
			{"subfinder", "-d", target, "-all", "-silent", "-o", tmp("subfinder.txt")},
			{"assetfinder", "--subs-only", target},
			{"amass", "enum", "-passive", "-d", target, "-nocolor"},
			{"amass", "subs", "-names", "-d", target, "-nocolor"},
			{"findomain", "-t", target, "-q"},
			{"dig", "@<nameserver>", target, "AXFR", "+time=5", "+tries=1"},
			resolve(tmp("passive_candidates.txt"), tmp("passive_resolved.txt"), true),
			{"dnsx", "-l", p.L.Path("01_unresolved.txt"), "-a", "-aaaa", "-silent", "-no-color", "-disable-update-check", "-threads", "100", "-rate-limit", itoa(minInt(p.prof.DNSRate, 500)), "-retry", "3", "-o", tmp("passive_recovered.txt")},
		}
	case "p2":
		return [][]string{brute(p.wl.Brute, target, tmp("brute.txt"), p.prof.DNSRate)}
	case "p3":
		return [][]string{brute(tmp("rec_words.txt"), "<parent>", tmp("rec/<parent>.txt"), p.prof.DNSRatePerWorker())}
	case "p4":
		return [][]string{
			{"gotator", "-sub", tmp("perm_seeds.txt"), "-perm", p.wl.Perms,
				"-depth", "1", "-numbers", "3", "-silent"},
			resolve(tmp("perms_raw.txt"), tmp("perms_resolved.txt"), false),
		}
	case "p5":
		return [][]string{
			{"httpx", "-l", p.L.Master(), "-json", "-o", p.L.Path("05_http.jsonl"),
				"-threads", itoa(p.prof.HTTPXThreads), "-timeout", "8", "-retries", "1",
				"-follow-redirects", "-tech-detect", "-title", "-status-code", "-silent", "-no-color"},
			{"tlsx", "-l", p.L.Master(), "-san", "-cn", "-silent"},
		}
	case "p6":
		mode := "connect"
		if os.Geteuid() == 0 {
			mode = "syn"
		}
		return [][]string{
			{"naabu", "-list", p.L.Master(), "-top-ports", "1000", "-o", p.L.Path("06_ports.txt"),
				"-rate", itoa(p.prof.NaabuRate), "-c", "50", "-scan-type", mode,
				"-silent", "-no-color", "-stats=false"},
			{"httpx", "-l", tmp("extra_ports.txt"), "-o", tmp("extra_urls.txt"),
				"-threads", itoa(p.prof.HTTPXThreads), "-timeout", "8", "-retries", "1", "-silent", "-no-color"},
		}
	case "p7":
		return [][]string{
			{"katana", "-list", tmp("live_urls.txt"), "-depth", "2", "-js-crawl",
				"-concurrency", itoa(p.prof.KatanaConc), "-rate-limit", "100", "-timeout", "10",
				"-silent", "-no-color", "-o", tmp("katana.txt")},
			{"waybackurls"},
			{"gau", "--subs", "--threads", "5"},
			resolve(tmp("crawled_candidates.txt"), tmp("crawled_resolved.txt"), true),
			{"dnsx", "-l", p.L.Path("07_unresolved.txt"), "-a", "-aaaa", "-silent", "-no-color", "-disable-update-check", "-threads", "100", "-rate-limit", itoa(minInt(p.prof.DNSRate, 500)), "-retry", "3", "-o", tmp("crawled_recovered.txt")},
			brute(tmp("deep_words.txt"), "<parent>", tmp("deep/<parent>.txt"), p.prof.DNSRatePerWorker()),
		}
	case "p8":
		return [][]string{p.nucleiCommand(tmp("live_urls.txt"))}
	case "p9":
		return [][]string{{"gowitness", "scan", "file", "-f", tmp("shot_urls.txt"),
			"--chrome-path", "<chrome>", "--screenshot-path", p.L.Report("screenshots"),
			"--write-db", "--timeout", "15"}}
	}
	return nil
}

func (p *Pipeline) nucleiCommand(liveFile string) []string {
	sev := "medium,high,critical"
	if p.opt.Deep {
		sev = "info,low,medium,high,critical"
	}
	return []string{"nuclei", "-l", liveFile, "-severity", sev, "-etags", "takeover",
		"-o", p.L.Report("nuclei.txt"), "-jsonl-export", p.L.Report("nuclei.jsonl"),
		"-rate-limit", "150", "-concurrency", itoa(p.prof.KatanaConc),
		"-timeout", "10", "-silent", "-no-color", "-stats-interval", "0"}
}
