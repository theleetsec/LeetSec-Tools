// Command leetenum runs the LeetEnum reconnaissance pipeline.
//
// The CLI is a switch statement over os.Args plus one flag.FlagSet per subcommand.
// That is the whole reason go.mod has no requires: a tool with five subcommands does
// not need an argument-parsing framework, and the framework is the thing that would
// have to be audited before this binary is allowed near a client engagement.
//
// Two behaviours are worth knowing about. A bare domain is accepted as the first
// argument, because `leetenum example.com` is what people actually type. And the first
// interrupt cancels the run context so the current phase can leave its artifacts and
// checkpoints behind, while a second one exits immediately — a scan holds subprocesses
// that take a moment to wind down, and an operator who presses Ctrl-C twice wants out.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/theleetsec/LeetSec-Tools/internal/host"
	"github.com/theleetsec/LeetSec-Tools/internal/scan"
	"github.com/theleetsec/LeetSec-Tools/internal/tools"
	"github.com/theleetsec/LeetSec-Tools/internal/ui"
)

// version is overridden at build time with -ldflags "-X main.version=...", so a
// release binary reports the tag it was cut from rather than whatever was hardcoded.
var version = "1.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		switch {
		case errors.Is(err, errSilent):
			// flag has already printed both the reason and the usage.
			os.Exit(2)
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			// Interrupted, not broken: the run directory is intact and resumable.
			fmt.Fprintln(os.Stderr, "leetenum: stopped; re-run the same command to resume")
			os.Exit(130)
		default:
			fmt.Fprintf(os.Stderr, "leetenum: %v\n", err)
			os.Exit(1)
		}
	}
}

// run dispatches one invocation. Unknown flags are an error rather than being
// ignored: the original shell parser fell through them silently, so `--profle beast`
// ran the default profile and said nothing about it.
func run(args []string) error {
	if len(args) == 0 {
		usage(os.Stdout)
		return nil
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	case "version", "--version", "-v":
		fmt.Printf("leetenum %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return nil
	case "scan":
		return cmdScan(args[1:])
	case "doctor":
		return cmdDoctor()
	case "install":
		return cmdInstall(args[1:])
	case "update":
		return cmdUpdate()
	}
	if strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("unknown option %q; run 'leetenum --help'", args[0])
	}
	// A bare domain: `leetenum example.com --deep`.
	return cmdScan(args)
}

// splitLeading pulls the leading non-flag arguments out before the flag package sees
// them. Go's flag parser stops at the first non-flag argument, so without this
// `leetenum example.com --deep` would parse zero flags and silently ignore --deep.
func splitLeading(args []string) (positional, rest []string) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			return args[:i], args[i:]
		}
	}
	return args, nil
}

// scanFlags is the option set, kept in one struct so the long and short forms of each
// flag are registered against the same variable rather than two that can disagree.
type scanFlags struct {
	domain, file, out, profile string
	only, skip, wordlist       string
	interval                   time.Duration
	deep, fresh, offline       bool
	monitor, dry, noColor      bool
	subs                       bool
	excludeFile, crawlBudget   string
	resumeCrawl                bool
}

func (f *scanFlags) register(fs *flag.FlagSet) {
	str := func(p *string, def, short, long, help string) {
		*p = def
		fs.StringVar(p, short, def, help)
		if long != "" {
			fs.StringVar(p, long, def, help)
		}
	}
	boolean := func(p *bool, short, long, help string) {
		fs.BoolVar(p, short, false, help)
		if long != "" {
			fs.BoolVar(p, long, false, help)
		}
	}
	str(&f.domain, "", "d", "domain", "target apex domain")
	str(&f.file, "", "f", "file", "file of domains, one per line")
	str(&f.out, defaultOutRoot(), "o", "output", "output root directory")
	str(&f.profile, "auto", "p", "profile", "lite | balanced | beast | auto")
	str(&f.only, "", "only", "", "run only these phases, e.g. p6,p9")
	str(&f.skip, "", "skip", "", "run everything except these phases")
	str(&f.wordlist, os.Getenv("LEETENUM_WORDLIST"), "wordlist", "", "override the brute-force wordlist")
	fs.DurationVar(&f.interval, "interval", 6*time.Hour, "monitor mode: wait between passes")
	boolean(&f.deep, "deep", "", "include low and info severity findings")
	boolean(&f.fresh, "fresh", "", "ignore checkpoints and start from phase one")
	boolean(&f.offline, "offline", "", "never fetch wordlists; use whatever is cached")
	boolean(&f.monitor, "m", "monitor", "loop, reporting what is new each pass")
	boolean(&f.dry, "dry-run", "", "print the commands and execute nothing")
	boolean(&f.noColor, "no-color", "", "disable colour (NO_COLOR is also honoured)")
	boolean(&f.subs, "subs", "", "subdomain hunt only: skip ports, nuclei, screenshots")
	str(&f.excludeFile, "", "exclude-file", "", "collection exclusions: exact names or *.suffix patterns")
	str(&f.crawlBudget, "", "crawl-budget", "", "crawl source budget: whole seconds/minutes/hours, e.g. 2h")
	boolean(&f.resumeCrawl, "resume-crawl", "", "continue only crawling from saved progress")
}

func cmdScan(args []string) error {
	leading, rest := splitLeading(args)

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	// flag calls Usage both for a parse error and for -h, and the two want different
	// streams and different exit codes. Both are handled after Parse, so this is
	// deliberately empty rather than printing a third variant of the same text.
	fs.Usage = func() {}
	var f scanFlags
	f.register(fs)
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// Asking for help is a request, not a mistake: stdout, exit zero.
			usage(os.Stdout)
			return nil
		}
		// flag has already named the offending option on stderr.
		usage(os.Stderr)
		return errSilent
	}

	// Positional domains can appear before the flags, after them, or both.
	targets, err := collectTargets(append(leading, fs.Args()...), f.domain, f.file)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("no target given: pass a domain, or -f with a file of them")
	}
	if f.noColor {
		os.Setenv("NO_COLOR", "1")
	}

	con, err := ui.New(os.Stdout, "")
	if err != nil {
		return err
	}
	defer con.Close()
	con.Banner(version, "reconnaissance pipeline — LeetSecurity LLC")

	h := host.Probe(f.out)
	warnMissing(con)

	ctx, stop := interrupt()
	defer stop()

	for pass := 1; ; pass++ {
		for _, t := range targets {
			if err := scanOne(ctx, con, h, f, t); err != nil {
				return err
			}
		}
		if !f.monitor || f.dry {
			return nil
		}
		// Each pass writes a new run directory, which is what makes the previous one
		// available as the differential baseline. --fresh applies to the first pass
		// only; carrying it forward would delete the baseline every time.
		f.fresh = false
		con.Info(fmt.Sprintf("Pass %d complete; next in %s.", pass, f.interval))
		if err := sleep(ctx, f.interval); err != nil {
			return err
		}
	}
}

// errSilent means the failure has already been reported: the flag package prints its
// own message, and repeating it prefixed with "leetenum:" is noise.
var errSilent = errors.New("")

// scanOne runs the pipeline once against one target. Each target gets its own run
// directory, its own state and its own transcript, so a file of fifty domains is fifty
// independent scans rather than one merged result set.
func scanOne(ctx context.Context, con *ui.Console, h host.Info, f scanFlags, target string) error {
	crawlBudget, err := scan.ParseCrawlBudget(f.crawlBudget)
	if err != nil {
		return err
	}
	p, err := scan.New(scan.Options{
		Target:      target,
		OutRoot:     f.out,
		Profile:     f.profile,
		Wordlist:    f.wordlist,
		Deep:        f.deep,
		Fresh:       f.fresh,
		Offline:     f.offline,
		Only:        phaseIDs(f.only),
		Skip:        phaseIDs(f.skip),
		DryRun:      f.dry,
		SubsOnly:    f.subs,
		ExcludeFile: f.excludeFile,
		CrawlBudget: crawlBudget,
		ResumeCrawl: f.resumeCrawl,
	}, h, con)
	if err != nil {
		return err
	}
	return p.Run(ctx)
}

// phaseIDs splits a --only/--skip value. Commas and spaces both separate, because both
// get typed, and an empty element is dropped rather than becoming a phase named "".
func phaseIDs(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, strings.ToLower(f))
		}
	}
	return out
}

// collectTargets gathers targets from positional arguments, -d and -f, in that order,
// deduplicating them. Duplicates matter: `leetenum example.com -d example.com` would
// otherwise run the same scan twice, the second pass resuming the first and reporting
// every host as already known.
func collectTargets(positional []string, domain, file string) ([]string, error) {
	var all []string
	all = append(all, positional...)
	if domain != "" {
		all = append(all, domain)
	}
	if file != "" {
		lines, err := scan.LoadLines(file)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", file, err)
		}
		all = append(all, lines...)
	}

	seen := make(map[string]bool, len(all))
	var out []string
	for _, t := range all {
		if strings.HasPrefix(t, "#") {
			continue
		}
		clean, ok := scan.CleanTarget(t)
		if !ok {
			return nil, fmt.Errorf("%q is not a domain name", t)
		}
		if !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	return out, nil
}

// interrupt returns a context cancelled by the first SIGINT or SIGTERM, and arranges
// for a second one to exit immediately.
//
// The first signal has to be catchable: phases flush their checkpoints as they finish,
// and cancelling the context lets the run stop at a resumable point instead of losing
// the hour it is in the middle of. The second is an escape hatch, because external
// tools do not always die when asked.
func interrupt() (context.Context, func()) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		fmt.Fprintln(os.Stderr, "\nleetenum: interrupted again — exiting now")
		os.Exit(130)
	}()
	return ctx, stop
}

// sleep waits, but stays interruptible: monitor mode spends almost all of its life in
// here, and a Ctrl-C during the wait should return rather than be ignored for six hours.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// defaultOutRoot is the working directory unless LEETENUM_OUTPUT_DIR says otherwise,
// matching the shell implementation so both write to the same place.
func defaultOutRoot() string {
	if d := os.Getenv("LEETENUM_OUTPUT_DIR"); d != "" {
		return d
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

// warnMissing reports absent required tools once, at startup, instead of letting the
// operator discover phase by phase that the scan cannot do anything. It is a warning
// and not an error: --dry-run needs no tools, and a partial toolchain still produces
// useful results.
func warnMissing(con *ui.Console) {
	inv := tools.Inventory()
	if missing := tools.MissingRequired(inv); len(missing) > 0 {
		con.Warn("Missing required tools: " + strings.Join(missing, ", "))
		con.Info("Install them with: leetenum install")
	}
	if !host.Have("massdns") {
		con.Warn("massdns is not installed, so puredns cannot resolve anything")
		con.Info(tools.MassdnsHint())
	}
}

// cmdDoctor reports the environment and exits non-zero when a required tool is
// missing, so it can be used as a gate in someone else's pipeline. It runs no network
// and installs nothing.
func cmdDoctor() error {
	con, err := ui.New(os.Stdout, "")
	if err != nil {
		return err
	}
	defer con.Close()
	con.Banner(version, "environment report")

	h := host.Probe(defaultOutRoot())
	con.SummaryOpen("Machine")
	con.SummaryRow("Platform", h.String(), ui.LevelNone)
	con.SummaryRow("CPU cores", strconv.Itoa(h.Cores), ui.LevelNone)
	con.SummaryRow("Memory", amount(h.RAMMB), level(h.RAMMB == 0, ui.LevelWarn, ui.LevelNone))
	con.SummaryRow("Free disk", amount(h.DiskMB), level(h.DiskMB > 0 && h.DiskMB < 5120, ui.LevelWarn, ui.LevelNone))
	con.SummaryRow("Scratch", h.Scratch, ui.LevelNone)
	con.SummaryRow("Go binaries", h.GoBin, ui.LevelNone)
	if v := tools.GoVersion(); v != "" {
		con.SummaryRow("Go toolchain", v, ui.LevelOK)
	} else {
		con.SummaryRow("Go toolchain", "not found — 'leetenum install' needs it", ui.LevelWarn)
	}
	if prof, err := scan.PickProfile("auto", h); err == nil {
		con.SummaryRow("Auto profile", prof.Name, ui.LevelNone)
	}
	con.SummaryClose()

	inv := tools.Inventory()
	con.SummaryOpen("Tools")
	for _, s := range inv {
		if s.Installed {
			con.SummaryRow(s.Tool.Name, s.Path, ui.LevelOK)
			continue
		}
		con.SummaryRow(s.Tool.Name, "not installed — "+s.Tool.Role,
			level(s.Tool.Required, ui.LevelErr, ui.LevelWarn))
	}
	for _, name := range tools.Helpers {
		if p := host.Which(name); p != "" {
			con.SummaryRow(name, p, ui.LevelOK)
		} else {
			con.SummaryRow(name, "not installed", ui.LevelWarn)
		}
	}
	con.SummaryClose()

	if !host.Have("massdns") {
		con.Warn("massdns is missing; phases 2 to 4 will find nothing without it")
		con.Info(tools.MassdnsHint())
	}
	if missing := tools.MissingRequired(inv); len(missing) > 0 {
		return fmt.Errorf("missing required tools: %s — run 'leetenum install'",
			strings.Join(missing, ", "))
	}
	con.Info("Everything required is present.")
	return nil
}

func amount(mb int) string {
	if mb <= 0 {
		return "unknown"
	}
	if mb >= 1024 {
		return fmt.Sprintf("%d MB (%.1f GB)", mb, float64(mb)/1024)
	}
	return fmt.Sprintf("%d MB", mb)
}

func level(cond bool, yes, no ui.Level) ui.Level {
	if cond {
		return yes
	}
	return no
}

// cmdInstall fetches the Go tools. It skips what is already present unless asked not
// to, so re-running it after a partial failure costs only the tools that failed.
func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	force := fs.Bool("force", os.Getenv("LEETENUM_FORCE") == "1", "reinstall tools already present")
	onlyReq := fs.Bool("required", false, "install only the tools a scan cannot run without")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // flag has already printed the two options
		}
		return errSilent
	}

	con, err := ui.New(os.Stdout, "")
	if err != nil {
		return err
	}
	defer con.Close()
	con.Banner(version, "dependency installer")

	v := tools.GoVersion()
	if v == "" {
		return fmt.Errorf("installing these tools needs the Go toolchain (%s or newer); "+
			"install Go, or use the container image instead", tools.GoMinVersion)
	}
	con.Detail("go", v)

	var want []tools.Tool
	for _, s := range tools.Inventory() {
		if *onlyReq && !s.Tool.Required {
			continue
		}
		if s.Installed && !*force {
			con.Detail(s.Tool.Name, "already installed")
			continue
		}
		want = append(want, s.Tool)
	}
	if len(want) == 0 {
		con.Info("Nothing to install. Run 'leetenum doctor' to confirm.")
		return nil
	}

	ctx, stop := interrupt()
	defer stop()
	if errs := installList(ctx, con, want); len(errs) > 0 {
		return fmt.Errorf("%d of %d tools did not install; the messages above say why",
			len(errs), len(want))
	}
	if !host.Have("massdns") {
		con.Warn("massdns has no Go package and was not installed")
		con.Info(tools.MassdnsHint())
	}
	con.Info("Done. Run 'leetenum doctor' to confirm.")
	return nil
}

// installList drives tools.Install with a console step per tool. The callbacks are what
// keep internal/tools free of any dependency on the terminal layer.
func installList(ctx context.Context, con *ui.Console, list []tools.Tool) []error {
	var st *ui.Step
	return tools.Install(ctx, list,
		func(t tools.Tool) {
			st = con.Start(fmt.Sprintf("Installing %s %s", t.Name, t.Version))
		},
		func(t tools.Tool, err error) {
			if st == nil {
				return
			}
			if err != nil {
				st.Failed(err.Error())
				return
			}
			st.OK(t.Role)
		})
}

// cmdUpdate reinstalls the tools at the versions this build pins and refreshes the
// nuclei templates.
//
// Reinstalling at the pinned versions is what "update" means here: the pins move with
// LeetEnum releases, so running this after upgrading the binary is what brings the
// toolchain in line with it. LEETENUM_UNPINNED=1 asks for @latest instead, which is
// occasionally what you want and is never what should happen by default — an
// unreproducible toolchain makes a finding impossible to re-verify later.
func cmdUpdate() error {
	con, err := ui.New(os.Stdout, "")
	if err != nil {
		return err
	}
	defer con.Close()
	con.Banner(version, "updating tools and templates")

	if tools.GoVersion() == "" {
		return fmt.Errorf("updating needs the Go toolchain (%s or newer)", tools.GoMinVersion)
	}
	list := make([]tools.Tool, len(tools.GoTools))
	copy(list, tools.GoTools)
	if os.Getenv("LEETENUM_UNPINNED") == "1" {
		con.Warn("LEETENUM_UNPINNED=1 — installing @latest rather than the pinned versions")
		for i := range list {
			list[i].Version = "latest"
		}
	}

	ctx, stop := interrupt()
	defer stop()
	errs := installList(ctx, con, list)

	if host.Have("nuclei") {
		st := con.Start("Updating nuclei templates")
		out, err := exec.CommandContext(ctx, "nuclei", "-update-templates", "-silent").CombinedOutput()
		if err != nil {
			st.Failed(lastLine(string(out)))
		} else {
			st.OK("")
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d of %d tools did not update", len(errs), len(list))
	}
	con.Info("Up to date.")
	return nil
}

// lastLine returns the final non-empty line, which is where a Go build or a template
// update puts the reason it failed.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return "no output"
}

// usage is written out by hand rather than assembled from the FlagSet.
//
// flag's own output lists every option twice — once per alias, since the short and long
// forms are separate registrations against the same variable — in alphabetical order,
// which puts --deep above --domain and reads nothing like the order these are used in.
//
// It goes to stdout when asked for and stderr when it accompanies an error, so
// `leetenum --help | less` works and a usage error does not pollute a redirected report.
func usage(w io.Writer) {
	fmt.Fprintf(w, `LeetEnum %s — reconnaissance pipeline (LeetSecurity LLC)

USAGE
  leetenum <domain> [options]           scan one target
  leetenum scan -d <domain> [options]   the same thing, said explicitly
  leetenum install                      install the tools a scan needs
  leetenum doctor                       report the environment, exit non-zero if broken
  leetenum update                       reinstall tools at pinned versions, update templates
  leetenum version

SCAN OPTIONS
  -d, --domain <domain>    target apex domain
  -f, --file <path>        file of domains, one per line ('#' comments allowed)
  -o, --output <dir>       output root (default: the current directory)
  -p, --profile <name>     lite | balanced | beast | auto (default: auto, sized from
                           this machine's cores and memory)
      --wordlist <path>    override the DNS brute-force wordlist
      --deep               include low and info severity findings
      --fresh              ignore checkpoints and start again from phase one
      --only <ids>         run only these phases, e.g. --only p5,p8
      --skip <ids>         run everything except these, e.g. --skip p6,p9
  -m, --monitor            loop, reporting what is new on each pass
      --interval <dur>     monitor wait between passes, e.g. 90m (default: 6h)
      --offline            never fetch wordlists; use whatever is cached
      --subs               subdomain hunt only (passive, brute, recurse, permute,
                           HTTP, crawl, deepen). Skip ports, nuclei, screenshots
      --dry-run            print the commands and execute nothing
      --no-color           disable colour (NO_COLOR is honoured too)
      --exclude-file <path> collection filters: exact names or *.suffix, one per line
      --crawl-budget <dur>  Katana/archive budget, e.g. 2h (default: Katana scales)
      --resume-crawl        continue only p7, keeping completed seed batches and URLs

PHASES
%s

EXAMPLES
  leetenum example.com
  leetenum example.com --subs
  leetenum example.com --profile beast --deep
  leetenum scan -d example.com --only p5,p8     re-probe and re-scan, nothing else
  leetenum scan -f targets.txt -o ~/engagements
  leetenum scan -d example.com --monitor --interval 1h

ENVIRONMENT
  LEETENUM_OUTPUT_DIR    default output root
  LEETENUM_WORDLIST      default brute-force wordlist
  LEETENUM_FORCE=1       'install' reinstalls tools already present
  LEETENUM_UNPINNED=1    'update' installs @latest instead of the pinned versions
  CHROME_PATH            browser to use for screenshots
  NO_COLOR               disable colour

An interrupted scan is resumable: run the same command again and it continues from
the phase it stopped in. Add --fresh to start over instead.

Exit codes: 0 success, 1 error, 2 bad usage, 130 interrupted.
`, version, scan.PhaseList())
}
