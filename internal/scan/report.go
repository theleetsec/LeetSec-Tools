package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/theleetsec/LeetSec-Tools/internal/ui"
)

// Reporting: the differential diff, the Markdown summary that can go straight into an
// engagement writeup, and the terminal block that mirrors it.

// severities are ordered highest first, which is the order they are counted in and the
// order they appear in the report. Leading with critical is the point: a reader who
// stops after the first section has still seen the findings that matter.
var severities = []string{"critical", "high", "medium", "low", "info"}

// countSeverity counts findings of one severity in nuclei's text output.
func countSeverity(path, sev string) int {
	return len(severityHits(path, sev, 0))
}

// severityHits returns matching lines, at most limit of them (0 for all).
//
// The bracketed tag is matched rather than the bare word, so a template named
// something like "wordpress-critical-plugin-rce" does not inflate the critical count.
// This only works because every tool inherits NO_COLOR and is passed -no-color: with
// escape sequences in the file the severity is not a contiguous string at all.
func severityHits(path, sev string, limit int) []string {
	lines, err := LoadLines(path)
	if err != nil {
		return nil
	}
	tag := "[" + sev + "]"
	var out []string
	for _, l := range lines {
		if strings.Contains(l, tag) {
			out = append(out, l)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

// diffPrevious writes reports/new_since_last_run.txt — the hosts in this run that were
// not in the newest completed earlier run — and returns them.
//
// The baseline is a master list from another run directory, captured by NewLayout
// before the `latest` pointer moved, which is the only moment the previous run is still
// identifiable. The original compared against a file inside the current run directory,
// so the difference was always empty and monitor mode reported nothing on every run it
// ever performed.
func (p *Pipeline) diffPrevious(master *Set) (*Set, error) {
	art := p.L.Report("new_since_last_run.txt")
	none := NewSet()

	if p.L.PrevMaster == "" || master.Len() == 0 {
		return none, p.empty(art)
	}
	// A resumed run's own master list is not a previous run.
	if sameFile(p.L.PrevMaster, p.L.Master()) {
		return none, p.empty(art)
	}

	prev, err := LoadSet(p.L.PrevMaster)
	if err != nil {
		return nil, err
	}
	appeared := master.Minus(prev)
	if err := appeared.WriteFile(art); err != nil {
		return nil, err
	}
	if n := appeared.Len(); n > 0 {
		p.con.Info(fmt.Sprintf("%d host(s) appeared since the previous run", n))
	} else {
		p.con.Info("No new hosts since the previous run")
	}
	return appeared, nil
}

// sameFile compares by identity rather than by string, so a symlinked, relative or
// otherwise differently spelled path to the same file is recognised as the same file.
func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// counts is what both the file and the terminal block report. Gathered once, from
// disk, so the two cannot disagree — and so a resumed run reports what is actually in
// the run directory rather than what this process happened to do.
type counts struct {
	dns      int
	live     int
	ports    int
	urls     int
	findings int
	appeared int
}

// writeReport publishes the durable live-URL list, writes reports/summary.md and
// mirrors it to the terminal.
func (p *Pipeline) writeReport(master, appeared *Set) error {
	_, urls, err := p.liveTargets()
	if err != nil {
		return err
	}
	// The scratch copy phases 8 to 10 consumed is deleted with the work directory, so
	// the list is published into the run directory as a result in its own right.
	if err := WriteLines(p.L.Path("master_live_urls.txt"), urls); err != nil {
		return err
	}

	c := counts{
		dns:      master.Len(),
		live:     len(urls),
		ports:    CountLines(p.L.Path("06_ports.txt")),
		urls:     CountLines(p.L.Path("07_urls.txt")),
		findings: CountLines(p.L.Report("nuclei.txt")),
		appeared: appeared.Len(),
	}
	if err := p.writeMarkdown(c); err != nil {
		return err
	}
	if err := p.writeManifest(c); err != nil {
		return err
	}
	p.reportTerminal(c)
	return nil
}

// writeManifest provides a stable machine-readable summary for CI and downstream
// reporting integrations. Counts are derived from the same durable artifacts as the
// Markdown report so the two cannot disagree.
func (p *Pipeline) writeManifest(c counts) error {
	m := struct {
		Version  string         `json:"version"`
		Target   string         `json:"target"`
		Profile  string         `json:"profile"`
		Platform string         `json:"platform"`
		Phases   []string       `json:"phases"`
		Counts   map[string]int `json:"counts"`
	}{"1.0.0", p.opt.Target, p.prof.Name, p.h.String(), PhaseIDs(), map[string]int{
		"resolved_hostnames": c.dns, "live_http_services": c.live, "open_ports": c.ports,
		"crawled_urls": c.urls, "vulnerability_findings": c.findings, "new_since_previous": c.appeared,
	}}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(p.L.Report("manifest.json"), b, 0o644)
}

// writeMarkdown builds reports/summary.md. Every count is paired with the file it came
// from, because the first question anyone asks about a number in a report is where to
// look to see the underlying data.
func (p *Pipeline) writeMarkdown(c counts) error {
	var b strings.Builder

	fmt.Fprintf(&b, "# LeetEnum report: %s\n\n", p.opt.Target)
	b.WriteString("| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Scan finished | %s |\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "| Duration | %s |\n", p.con.Elapsed())
	fmt.Fprintf(&b, "| Profile | %s (%d cores, %d MB RAM) |\n", p.prof.Name, p.h.Cores, p.h.RAMMB)
	fmt.Fprintf(&b, "| Platform | %s |\n", p.h.String())
	if p.L.PrevMaster != "" {
		fmt.Fprintf(&b, "| Compared against | `%s` |\n", filepath.Base(filepath.Dir(p.L.PrevMaster)))
	}

	b.WriteString("\n## Results\n\n")
	b.WriteString("| Metric | Count | File |\n|---|---:|---|\n")
	for _, row := range []struct {
		label string
		n     int
		file  string
	}{
		{"Resolved hostnames", c.dns, "master_dns.txt"},
		{"Live HTTP services", c.live, "master_live_urls.txt"},
		{"Open ports", c.ports, "06_ports.txt"},
		{"Crawled URLs", c.urls, "07_urls.txt"},
		{"Vulnerability findings", c.findings, "reports/nuclei.txt"},
		{"New since previous run", c.appeared, "reports/new_since_last_run.txt"},
	} {
		fmt.Fprintf(&b, "| %s | %d | `%s` |\n", row.label, row.n, row.file)
	}

	p.markdownFindings(&b)
	b.WriteString("\n---\n\nGenerated by LeetEnum. LeetSecurity LLC.\n")

	return os.WriteFile(p.L.Report("summary.md"), []byte(b.String()), 0o644)
}

// markdownFindings inlines the findings themselves, highest severity first and capped
// per severity. The report leads with what matters instead of making the reader open
// another file to find out whether anything was found at all.
func (p *Pipeline) markdownFindings(b *strings.Builder) {
	nuclei := p.L.Report("nuclei.txt")
	if CountLines(nuclei) > 0 {
		b.WriteString("\n## Findings by severity\n")
		for _, sev := range severities {
			hits := severityHits(nuclei, sev, maxInlineFindings)
			if len(hits) == 0 {
				continue
			}
			fmt.Fprintf(b, "\n### %s\n\n```\n%s\n```\n", sev, strings.Join(hits, "\n"))
		}
	}
}

const maxInlineFindings = 25

// reportTerminal prints the closing block. Hostnames are flagged when there are none —
// a scan that resolved nothing is a configuration problem, not a clean result — and
// findings are flagged when there are any.
func (p *Pipeline) reportTerminal(c counts) {
	p.con.SummaryOpen("Scan complete: " + p.opt.Target)
	p.con.SummaryRow("Duration", p.con.Elapsed().String(), ui.LevelNone)
	p.con.SummaryRow("Profile", p.prof.Name, ui.LevelNone)
	p.con.SummaryRow("Resolved hostnames", itoa(c.dns), level(c.dns > 0, ui.LevelOK, ui.LevelWarn))
	p.con.SummaryRow("Live HTTP services", itoa(c.live), ui.LevelNone)
	p.con.SummaryRow("Open ports", itoa(c.ports), ui.LevelNone)
	p.con.SummaryRow("Crawled URLs", itoa(c.urls), ui.LevelNone)
	p.con.SummaryRow("Findings", itoa(c.findings),
		level(c.findings > 0, ui.LevelWarn, ui.LevelNone))
	if c.appeared > 0 {
		p.con.SummaryRow("New since last run", itoa(c.appeared), ui.LevelOK)
	}
	p.con.SummaryClose()
	p.con.Info("Output:  " + p.L.Run)
	p.con.Info("Report:  " + p.L.Report("summary.md"))
}

func level(cond bool, yes, no ui.Level) ui.Level {
	if cond {
		return yes
	}
	return no
}
