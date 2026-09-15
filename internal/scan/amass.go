package scan

import (
	"context"
	"time"
)

// v4 and v5 store discoveries in the configured asset database. In v5 enum -o
// was removed, and enum stdout is a scope summary rather than a hostname list.
// Export through subs using the same default config/database as enumeration.
// Never replace the operator's engine/database config with an empty -dir.
func (p *Pipeline) amass(ctx context.Context, into *Set) {
	if !p.need("amass", "amass") {
		p.optionalWarning("amass: not installed; other passive sources remain enabled")
		return
	}
	r := p.derive()
	r.Optional, r.InterruptOnCancel = true, true
	bctx, cancel := budget(ctx, 10*time.Minute)
	res := p.execOn(bctx, r, "amass enumeration (10m budget)", "amass", p.L.Path("amass-enum.stdout"),
		"amass", "enum", "-passive", "-d", p.opt.Target, "-nocolor")
	cancel()
	if ctx.Err() != nil || (res.Err != nil && !res.TimedOut) {
		return
	}
	bctx, cancel = budget(ctx, 2*time.Minute)
	defer cancel()
	out := p.L.Path("amass-names.txt")
	p.execOn(bctx, r, "Exporting amass discovered names", "amass_subs", out,
		"amass", "subs", "-names", "-d", p.opt.Target, "-nocolor")
	p.absorb(into, out) // retain valid partial output as well as complete exports
}
