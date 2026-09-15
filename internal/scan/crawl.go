package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var durationPattern = regexp.MustCompile(`^([1-9][0-9]*)([smh]?)$`)

// ParseCrawlBudget uses the same whole-unit grammar as Bash, bounded to seven days.
func ParseCrawlBudget(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	m := durationPattern.FindStringSubmatch(value)
	if m == nil {
		return 0, fmt.Errorf("crawl budget must be whole seconds, minutes or hours, e.g. 2700, 45m, 2h")
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	unit := int64(1)
	if m[2] == "m" {
		unit = 60
	}
	if m[2] == "h" {
		unit = 3600
	}
	if err != nil || n > 604800/unit {
		return 0, fmt.Errorf("crawl budget must be at most 168h")
	}
	return time.Duration(n*unit) * time.Second, nil
}

func crawlBudget(seeds int) time.Duration {
	blocks := (seeds + 999) / 1000
	if blocks < 1 {
		blocks = 1
	}
	if blocks > 8 {
		blocks = 8
	}
	return time.Duration(blocks) * 45 * time.Minute
}

var crawlProgressFiles = []string{"07_katana_done_urls.txt", "07_katana_urls.txt", "07_wayback_urls.txt", "07_gau_urls.txt", "07_wayback_complete", "07_gau_complete", "07_crawl_pending.txt", "07_katana_attempt.txt", "07_wayback_attempt.txt", "07_gau_attempt.txt"}

func (p *Pipeline) clearCrawlProgress() error {
	for _, name := range crawlProgressFiles {
		if err := os.Remove(p.L.Path(name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (p *Pipeline) keepCrawlOutput(dst, src string) error {
	old, err := LoadLines(dst)
	if err != nil {
		return err
	}
	newLines, err := LoadLines(src)
	if err != nil {
		return err
	}
	return WriteLines(dst, p.collectedURLs(append(old, newLines...)))
}

// Checkpoint completed seed batches, never a timed-out batch. Output from every
// attempt is merged before returning. Continuation retries only unfinished work.
func (p *Pipeline) crawlURLs(ctx context.Context, liveFile string) ([]string, error) {
	live, err := LoadLines(liveFile)
	if err != nil {
		return nil, err
	}
	live = p.collectedURLs(live)
	limit := p.opt.CrawlBudget
	if limit == 0 {
		limit = crawlBudget(len(live))
	}
	var pending []string
	var incomplete error
	for _, source := range []string{"katana", "wayback", "gau"} {
		if err := p.keepCrawlOutput(p.L.Path("07_"+source+"_urls.txt"), p.L.Path("07_"+source+"_attempt.txt")); err != nil {
			return nil, err
		}
	}
	if len(live) == 0 {
		var urls []string
		for _, source := range []string{"katana", "wayback", "gau"} {
			lines, err := LoadLines(p.L.Path("07_" + source + "_urls.txt"))
			if err != nil {
				return nil, err
			}
			urls = append(urls, lines...)
		}
		return urls, nil
	}
	if p.need("katana", "crawling") {
		donePath := p.L.Path("07_katana_done_urls.txt")
		doneLines, err := LoadLines(donePath)
		if err != nil {
			return nil, err
		}
		done := map[string]bool{}
		for _, u := range doneLines {
			done[u] = true
		}
		var remaining []string
		for _, u := range live {
			if !done[u] {
				remaining = append(remaining, u)
			}
		}
		bctx, cancel := budget(ctx, limit)
		for start := 0; start < len(remaining); start += 100 {
			if err := bctx.Err(); err != nil {
				pending = append(pending, "katana")
				incomplete = errors.Join(incomplete, err)
				break
			}
			end := minInt(start+100, len(remaining))
			batch := remaining[start:end]
			in, out := p.L.Temp("katana-input.txt"), p.L.Path("07_katana_attempt.txt")
			if err := os.WriteFile(out, nil, 0o644); err != nil {
				cancel()
				return nil, err
			}
			if err := WriteLines(in, batch); err != nil {
				cancel()
				return nil, err
			}
			r := p.derive()
			r.Optional, r.InterruptOnCancel = true, true
			res := p.execOn(bctx, r, fmt.Sprintf("Crawling seed batch (%s total budget)", limit), "katana", "",
				"katana", "-list", in, "-depth", "2", "-js-crawl", "-concurrency", itoa(p.prof.KatanaConc),
				"-rate-limit", "100", "-timeout", "10", "-silent", "-no-color", "-o", out)
			if err := p.keepCrawlOutput(p.L.Path("07_katana_urls.txt"), out); err != nil {
				cancel()
				return nil, err
			}
			if res.Err != nil || bctx.Err() != nil {
				pending = append(pending, "katana")
				if res.TimedOut || bctx.Err() != nil || res.ExitCode == 124 {
					incomplete = errors.Join(incomplete, bctx.Err(), res.Err)
				}
				break
			}
			for _, u := range batch {
				done[u] = true
			}
			var all []string
			for u := range done {
				all = append(all, u)
			}
			if err := WriteLines(donePath, all); err != nil {
				cancel()
				return nil, err
			}
		}
		cancel()
	} else {
		p.optionalWarning("katana: not installed")
	}
	for _, src := range []struct {
		bin, name string
		args      []string
	}{
		{"waybackurls", "wayback", []string{"waybackurls"}},
		{"gau", "gau", []string{"gau", "--subs", "--threads", "5"}},
	} {
		marker := p.L.Path("07_" + src.name + "_complete")
		if _, err := os.Stat(marker); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		if ctx.Err() != nil {
			incomplete = errors.Join(incomplete, ctx.Err())
			break
		}
		if !p.need(src.bin, "archive mining") {
			p.optionalWarning(src.bin + ": not installed")
			continue
		}
		r := p.derive()
		r.Optional = true
		r.Stdin = strings.NewReader(p.opt.Target + "\n")
		archiveLimit := 10 * time.Minute
		if p.opt.CrawlBudget > 0 {
			archiveLimit = p.opt.CrawlBudget
		}
		bctx, cancel := budget(ctx, archiveLimit)
		out := p.L.Path("07_" + src.name + "_attempt.txt")
		res := p.execOn(bctx, r, fmt.Sprintf("%s archive mining (%s budget)", src.bin, archiveLimit), src.bin, out, src.args...)
		cancel()
		if err := p.keepCrawlOutput(p.L.Path("07_"+src.name+"_urls.txt"), out); err != nil {
			return nil, err
		}
		if res.Err == nil {
			if err := os.WriteFile(marker, []byte("complete\n"), 0o644); err != nil {
				return nil, err
			}
		} else {
			pending = append(pending, src.bin)
			if res.TimedOut || res.ExitCode == 124 {
				incomplete = errors.Join(incomplete, fmt.Errorf("%s archive budget expired; continuation available", src.bin))
			}
		}
	}
	if err := WriteLines(p.L.Path("07_crawl_pending.txt"), pending); err != nil {
		return nil, err
	}
	var urls []string
	for _, name := range []string{"07_katana_urls.txt", "07_wayback_urls.txt", "07_gau_urls.txt"} {
		lines, err := LoadLines(p.L.Path(name))
		if err != nil {
			return nil, err
		}
		urls = append(urls, lines...)
	}
	if incomplete != nil {
		p.con.Warn("Crawl budget exhausted; use --resume-crawl --crawl-budget 2h to continue saved work")
	}
	return urls, incomplete
}
