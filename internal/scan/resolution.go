package scan

import (
	"context"
	"errors"
	"fmt"
)

// Resolve collected candidates without wildcard suppression. The massdns-backed
// first pass is only an accelerator: missed names get an independent A/AAAA pass
// with bounded concurrency and retries. Keep input and misses for continuation.
func (p *Pipeline) resolveCandidates(ctx context.Context, candidates *Set, what string) (*Set, error) {
	candidates = p.allowed(candidates)
	inputName, ok := map[string]string{"passive": "01_candidates.txt", "crawled": "07_candidates.txt"}[what]
	if !ok {
		return nil, fmt.Errorf("unknown candidate class %q", what)
	}
	in := p.L.Path(inputName)
	previous, err := LoadSet(in)
	if err != nil {
		return nil, err
	}
	candidates.Merge(p.allowed(previous))
	if err := candidates.WriteFile(in); err != nil {
		return nil, err
	}
	found := NewSet()
	if what == "crawled" {
		known, err := LoadSet(p.L.Master())
		if err != nil {
			return nil, err
		}
		found.Merge(p.allowed(known).Intersect(candidates))
	}
	bulkCandidates := candidates.Minus(found)
	bulkInput := p.L.Temp(what + "_bulk_candidates.txt")
	if err := bulkCandidates.WriteFile(bulkInput); err != nil {
		return found, err
	}
	if bulkCandidates.Len() > 0 && p.need("puredns", what+" bulk resolution") {
		out := p.L.Temp(what + "_bulk.txt")
		p.execOptional(ctx, "Bulk resolving "+what+" candidates", "resolve_"+what, "",
			"puredns", "resolve", bulkInput, "-r", p.wl.Resolvers, "-w", out,
			"--rate-limit", itoa(p.prof.DNSRate), "--skip-wildcard-filter", "--skip-validation", "--skip-sanitize")
		s, err := LoadSet(out)
		if err != nil {
			return nil, err
		}
		found.Merge(p.allowed(s).Intersect(candidates))
	}
	missing := candidates.Minus(found)
	missPath := p.L.Path(map[string]string{"passive": "01_unresolved.txt", "crawled": "07_unresolved.txt"}[what])
	if err := missing.WriteFile(missPath); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return found, err
	}
	if missing.Len() > 0 {
		if !p.need("dnsx", what+" A/AAAA recovery") {
			return found, fmt.Errorf("dnsx is required to verify %d missed %s candidates", missing.Len(), what)
		}
		out := p.L.Temp(what + "_recovered.txt")
		rate := minInt(p.prof.DNSRate, 500)
		res := p.exec(ctx, "Retrying "+itoa(missing.Len())+" missed "+what+" names (A/AAAA)", "recover_"+what, "",
			"dnsx", "-l", missPath, "-a", "-aaaa", "-silent", "-no-color", "-disable-update-check",
			"-threads", "100", "-rate-limit", itoa(rate), "-retry", "3", "-o", out)
		s, err := LoadSet(out)
		if err != nil {
			return found, err
		}
		found.Merge(p.allowed(s).Intersect(candidates))
		missing = candidates.Minus(found)
		if err := missing.WriteFile(missPath); err != nil {
			return found, err
		}
		if res.Err != nil {
			return found, res.Err
		}
	}
	p.con.Detail("unresolved candidates retained", missing.Len())
	return found, nil
}

// Keep artifacts even when resolution is interrupted; never checkpoint the error.
func (p *Pipeline) resolveInto(ctx context.Context, art string, candidates *Set, what string) error {
	found, err := p.resolveCandidates(ctx, candidates, what)
	if found != nil {
		err = errors.Join(err, found.WriteFile(art))
	}
	return err
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
