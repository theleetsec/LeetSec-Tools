// Package ui is the terminal layer: one place that decides what the operator
// sees, so no other package needs to know whether it is attached to a terminal.
//
// Three rules shape it.
//
// Every line that reaches the screen is also written to the run log with the
// escape sequences stripped and a timestamp added. A recon run is evidence, and a
// log full of ANSI noise is unusable in a report.
//
// Nothing is emitted that a non-terminal cannot handle. Piped, redirected, or run
// under CI, the output degrades to plain timestamped lines with no cursor tricks —
// the spinner in particular is silently skipped rather than writing thousands of
// carriage returns into a file.
//
// The palette is muted on purpose. This output ends up in client-facing
// screenshots, so it uses low-saturation 256-colour values and no emoji.
package ui

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type style struct {
	dim, accent, ok, warn, err, rule, bold, reset string
}

var muted = style{
	dim:    "\x1b[38;5;245m",
	accent: "\x1b[38;5;109m",
	ok:     "\x1b[38;5;108m",
	warn:   "\x1b[38;5;179m",
	err:    "\x1b[38;5;167m",
	rule:   "\x1b[38;5;240m",
	bold:   "\x1b[1m",
	reset:  "\x1b[0m",
}

// Sixteen-colour fallback for terminals that do not advertise 256 colours.
var basic = style{
	dim:    "\x1b[90m",
	accent: "\x1b[36m",
	ok:     "\x1b[32m",
	warn:   "\x1b[33m",
	err:    "\x1b[31m",
	rule:   "\x1b[90m",
	bold:   "\x1b[1m",
	reset:  "\x1b[0m",
}

var plain = style{}

type glyphs struct {
	bullet, hline string
	spin          []string
}

var unicodeGlyphs = glyphs{
	bullet: "·",
	hline:  "─",
	spin:   []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
}

var asciiGlyphs = glyphs{
	bullet: "-",
	hline:  "-",
	spin:   []string{"|", "/", "-", "\\"},
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// Console carries the output state for a run. One is created at startup and
// passed down; nothing in the pipeline writes to stdout directly.
type Console struct {
	mu    sync.Mutex
	out   io.Writer
	log   io.WriteCloser
	st    style
	g     glyphs
	tty   bool
	width int
	start time.Time

	// Active spinner, if any.
	spinStop chan struct{}
	spinDone chan struct{}

	// Running totals shown on the spinner line so the operator can see the
	// hunt growing without waiting for the phase to finish.
	names, resolved, live int
}

// New builds a Console. logPath may be empty, in which case nothing is mirrored;
// a log that cannot be opened is reported but is not fatal, because losing the
// transcript is not a reason to abandon a scan that is otherwise fine.
func New(out io.Writer, logPath string) (*Console, error) {
	c := &Console{out: out, start: time.Now(), width: termWidth()}
	c.tty = isTerminal(out)
	c.st = pickStyle(c.tty)
	c.g = pickGlyphs()
	if logPath == "" {
		return c, nil
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return c, fmt.Errorf("run log %s: %w", logPath, err)
	}
	c.log = f
	return c, nil
}

// SetLog attaches (or replaces) the transcript file after construction.
//
// It exists because of an ordering problem: the log belongs inside the run
// directory, and the run directory is chosen by the pipeline, which needs a Console
// to report what it chose. So the Console starts without a log and is given one as
// soon as there is somewhere to put it. Failing to open it is reported by the caller
// and is not fatal — losing the transcript is not a reason to abandon the scan.
func (c *Console) SetLog(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("run log %s: %w", path, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.log != nil {
		_ = c.log.Close()
	}
	c.log = f
	return nil
}

func (c *Console) Close() {
	c.StopSpinner()
	if c.log != nil {
		_ = c.log.Close()
	}
}

// IsTTY lets callers decide whether an interactive prompt makes sense.
func (c *Console) IsTTY() bool { return c.tty }

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	// A character device is the portable stdlib test. It is true for a terminal
	// and false for a pipe, a file, or a socket, which is exactly the distinction
	// that matters here.
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func pickStyle(tty bool) style {
	if !tty || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return plain
	}
	term := os.Getenv("TERM")
	if os.Getenv("COLORTERM") != "" || strings.Contains(term, "256") ||
		strings.Contains(term, "truecolor") || term == "xterm-kitty" ||
		strings.HasPrefix(term, "alacritty") {
		return muted
	}
	return basic
}

// pickGlyphs decides between box-drawing characters and ASCII. Go always writes
// UTF-8, so the question is only whether the terminal will render it; the locale
// environment is the available signal, and macOS terminals are UTF-8 regardless
// of what LANG says.
func pickGlyphs() glyphs {
	for _, v := range []string{os.Getenv("LC_ALL"), os.Getenv("LC_CTYPE"), os.Getenv("LANG")} {
		if v == "" {
			continue
		}
		if strings.Contains(strings.ToLower(strings.ReplaceAll(v, "-", "")), "utf8") {
			return unicodeGlyphs
		}
		// An explicit non-UTF-8 locale is a decision, not an absence.
		return asciiGlyphs
	}
	return asciiGlyphs
}

func termWidth() int {
	// Reading the real window size needs an ioctl, which would pull in build-tagged
	// syscall code for one cosmetic value. COLUMNS is exported by most shells and
	// 100 is a reasonable default when it is not.
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 40 && n <= 300 {
			return n
		}
	}
	return 100
}

// ---------------------------------------------------------------------------
// Emission. Everything funnels through emit, which is the only place that writes
// to the screen and the log, so the two can never disagree about what happened.
// ---------------------------------------------------------------------------

func (c *Console) emit(screen, logged string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearSpinnerLine()
	fmt.Fprintln(c.out, screen)
	if c.log == nil {
		return
	}
	if logged == "" {
		logged = ansiRE.ReplaceAllString(screen, "")
	}
	fmt.Fprintf(c.log, "%s %s\n", time.Now().Format("15:04:05"), strings.TrimRight(logged, " "))
}

// clearSpinnerLine erases a partially drawn spinner so the next real line does not
// land on top of it. Caller holds the lock.
func (c *Console) clearSpinnerLine() {
	if c.tty && c.spinStop != nil {
		fmt.Fprint(c.out, "\r\x1b[2K")
	}
}

// Repeat builds a rule of n glyphs. Written with strings.Repeat rather than the
// shell's printf padding trick, so multibyte glyphs count as one character
// regardless of locale — the class of bug that made the bash version draw rules
// three times too long under LC_ALL=C.
func (c *Console) Repeat(n int) string {
	if n < 1 {
		return ""
	}
	return strings.Repeat(c.g.hline, n)
}

func (c *Console) Elapsed() time.Duration { return time.Since(c.start).Round(time.Second) }

// Banner is deliberately two lines of text and a rule rather than ASCII art. The
// version and the target are the two things worth screenshotting.
func (c *Console) Banner(version, subtitle string) {
	rule := c.Repeat(min(42, c.width-2))
	c.emit("", "")
	title := c.st.bold + c.st.accent + "leetenum" + c.st.reset
	ver := c.st.dim + version + c.st.reset
	sub := c.st.dim + subtitle + c.st.reset
	c.emit("  "+title+"  "+ver+"   "+sub, "leetenum "+version+"  "+subtitle)
	c.emit("  "+c.st.dim+"·•◦•·•◦•·•◦•·•◦•·•◦•·•◦•"+c.st.reset, "  ·•◦•")
	c.emit("  "+c.st.rule+rule+c.st.reset, "  "+strings.Repeat("-", 24))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SetStat updates a running counter shown on the live spinner line.
func (c *Console) SetStat(key string, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch key {
	case "names":
		c.names = n
	case "resolved":
		c.resolved = n
	case "live":
		c.live = n
	}
}

// Phase prints the section header. The logged form is the one the test suite and
// `--resume` diagnostics grep for, so its shape is part of the interface:
//
//	14:03:22 === [3/10] Recursive enumeration (elapsed 2m11s)
func (c *Console) Phase(n, total int, title string) {
	head := fmt.Sprintf("[%d/%d]", n, total)
	c.Blank()
	c.emit(fmt.Sprintf("%s%s%s %s%s%s %s(elapsed %s)%s",
		c.st.accent, head, c.st.reset,
		c.st.bold, title, c.st.reset,
		c.st.dim, c.Elapsed(), c.st.reset),
		fmt.Sprintf("=== %s %s (elapsed %s)", head, title, c.Elapsed()))
}

// Blank separates sections on screen without writing a timestamped empty line
// into the log, where it would just be noise.
func (c *Console) Blank() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearSpinnerLine()
	fmt.Fprintln(c.out)
	if c.log != nil {
		fmt.Fprintln(c.log)
	}
}

func (c *Console) Info(msg string) {
	c.emit(fmt.Sprintf("  %s%s%s %s", c.st.dim, c.g.bullet, c.st.reset, msg), "  "+msg)
}

func (c *Console) Warn(msg string) {
	c.emit(fmt.Sprintf("  %swarn%s %s", c.st.warn, c.st.reset, msg), "  warn "+msg)
}

func (c *Console) Err(msg string) {
	c.emit(fmt.Sprintf("  %sfail%s %s", c.st.err, c.st.reset, msg), "  fail "+msg)
}

// Detail is the key/value form used for counts, aligned so a column of them reads
// as a table without drawing one.
func (c *Console) Detail(key string, value any) {
	c.emit(fmt.Sprintf("      %s%-28s%s %v", c.st.dim, key, c.st.reset, value),
		fmt.Sprintf("      %-28s %v", key, value))
}

// ---------------------------------------------------------------------------
// Steps.
//
// A step is one external command. It answers the question the original tool left
// open — is this thing still working, or has it hung? — by animating while the
// command runs and then replacing the animation with a result line carrying the
// duration.
//
// On a non-terminal there is no animation: the start line is printed immediately
// so a piped log shows the command beginning rather than only its outcome, which
// is what you want when a scan dies halfway.
// ---------------------------------------------------------------------------

// Step is returned by Start and closed by exactly one of OK, Failed or Skipped.
type Step struct {
	c     *Console
	msg   string
	begun time.Time
}

func (c *Console) Start(msg string) *Step {
	s := &Step{c: c, msg: msg, begun: time.Now()}
	if c.tty {
		c.startSpinner(msg)
	} else {
		c.emit(fmt.Sprintf("  %s...%s %s", c.st.dim, c.st.reset, msg), "  ... "+msg)
	}
	return s
}

func (s *Step) took() string {
	return time.Since(s.begun).Round(time.Second).String()
}

// OK closes the step successfully. note is optional and is where a count belongs.
func (s *Step) OK(note string) {
	s.c.StopSpinner()
	tail := ""
	if note != "" {
		tail = " " + note
	}
	s.c.emit(fmt.Sprintf("  %sok%s   %s%s %s(%s)%s",
		s.c.st.ok, s.c.st.reset, s.msg, tail, s.c.st.dim, s.took(), s.c.st.reset),
		fmt.Sprintf("  ok   %s%s (%s)", s.msg, tail, s.took()))
}

// Failed closes the step with a reason. It is not fatal by itself: a recon phase
// whose tool exits non-zero still leaves the pipeline able to continue, and the
// caller decides.
func (s *Step) Failed(reason string) {
	s.c.StopSpinner()
	s.c.emit(fmt.Sprintf("  %sfail%s %s %s(%s)%s\n       %s%s%s",
		s.c.st.err, s.c.st.reset, s.msg, s.c.st.dim, s.took(), s.c.st.reset,
		s.c.st.dim, reason, s.c.st.reset),
		fmt.Sprintf("  fail %s (%s): %s", s.msg, s.took(), reason))
}

// Skipped closes the step without having run it, which is the common case for an
// optional tool that is not installed. Saying so plainly is the point: the
// original tool skipped silently and looked as though it had scanned.
func (s *Step) Skipped(why string) {
	s.c.StopSpinner()
	s.c.emit(fmt.Sprintf("  %sskip%s %s %s(%s)%s",
		s.c.st.warn, s.c.st.reset, s.msg, s.c.st.dim, why, s.c.st.reset),
		fmt.Sprintf("  skip %s (%s)", s.msg, why))
}

// ---------------------------------------------------------------------------
// Spinner. One goroutine, started and stopped under the same mutex the emitters
// use, so a line printed from a phase can never interleave with a frame.
// ---------------------------------------------------------------------------

func (c *Console) startSpinner(msg string) {
	c.mu.Lock()
	if c.spinStop != nil {
		c.mu.Unlock()
		c.StopSpinner()
		c.mu.Lock()
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	c.spinStop, c.spinDone = stop, done
	frames := c.g.spin
	dim, reset, accent := c.st.dim, c.st.reset, c.st.accent
	out := c.out
	c.mu.Unlock()

	go func() {
		defer close(done)
		t := time.NewTicker(110 * time.Millisecond)
		defer t.Stop()
		begun := time.Now()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-t.C:
				c.mu.Lock()
				stats := ""
				if c.names+c.resolved+c.live > 0 {
					stats = fmt.Sprintf("  %snames %d  resolved %d  live %d%s",
						dim, c.names, c.resolved, c.live, reset)
				}
				fmt.Fprintf(out, "\r\x1b[2K  %s%s%s %s %s%s%s%s",
					accent, frames[i%len(frames)], reset, msg,
					dim, time.Since(begun).Round(time.Second), reset, stats)
				c.mu.Unlock()
			}
		}
	}()
}

// StopSpinner is safe to call when no spinner is running, which is what makes it
// usable from Close and from every step terminator without bookkeeping.
func (c *Console) StopSpinner() {
	c.mu.Lock()
	stop, done := c.spinStop, c.spinDone
	c.spinStop, c.spinDone = nil, nil
	c.mu.Unlock()
	if stop == nil {
		return
	}
	close(stop)
	<-done
	c.mu.Lock()
	fmt.Fprint(c.out, "\r\x1b[2K")
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Summary tables, used by `doctor` and by the end-of-run report.
// ---------------------------------------------------------------------------

type Level int

const (
	LevelNone Level = iota
	LevelOK
	LevelWarn
	LevelErr
)

func (c *Console) SummaryOpen(title string) {
	c.Blank()
	c.emit(fmt.Sprintf("  %s%s%s", c.st.bold, title, c.st.reset), "  "+title)
	rule := c.Repeat(c.width - 4)
	c.emit("  "+c.st.rule+rule+c.st.reset, "  "+rule)
}

func (c *Console) SummaryRow(key, value string, lvl Level) {
	colour := ""
	switch lvl {
	case LevelOK:
		colour = c.st.ok
	case LevelWarn:
		colour = c.st.warn
	case LevelErr:
		colour = c.st.err
	}
	reset := ""
	if colour != "" {
		reset = c.st.reset
	}
	c.emit(fmt.Sprintf("  %s%-24s%s %s%s%s", c.st.dim, key, c.st.reset, colour, value, reset),
		fmt.Sprintf("  %-24s %s", key, value))
}

func (c *Console) SummaryClose() {
	rule := c.Repeat(c.width - 4)
	c.emit("  "+c.st.rule+rule+c.st.reset, "  "+rule)
}

// Progress draws a compact bar for the phases whose work is countable. It is a
// single redrawn line on a terminal and one line per call elsewhere, so piping a
// run does not produce a thousand progress lines: callers pass done==total for the
// final call and nothing in between when not a TTY.
func (c *Console) Progress(label string, done, total int) {
	if total <= 0 {
		return
	}
	if !c.tty && done != total {
		return
	}
	const w = 24
	filled := done * w / total
	if filled > w {
		filled = w
	}
	bar := strings.Repeat(c.g.hline, filled) + strings.Repeat(" ", w-filled)
	line := fmt.Sprintf("  %s%s%s [%s%s%s] %d/%d",
		c.st.dim, label, c.st.reset, c.st.accent, bar, c.st.reset, done, total)
	if c.tty && done != total {
		c.mu.Lock()
		fmt.Fprint(c.out, "\r\x1b[2K"+line)
		c.mu.Unlock()
		return
	}
	c.emit(line, fmt.Sprintf("  %s [%d/%d]", label, done, total))
}
