package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Runner executes external tools.
//
// There is no shell anywhere in this file, and that is the design. The original
// pipeline built command strings and passed them to `eval`, so any hostname a
// third-party tool emitted became shell input — a name containing a backtick or a
// semicolon was arbitrary code execution triggered by whatever the target's DNS
// happened to serve. Here a command is a string slice and the operating system
// execs it directly; there is no metacharacter to quote because nothing parses one.
type Runner struct {
	// LogDir receives one file per command, named after the step.
	LogDir string
	// Timeout applies per command. Zero means no limit.
	Timeout time.Duration
	// Env entries are appended to the process environment, "KEY=value".
	Env []string
	// Stdin, when set, is fed to the command. Some tools take their target on
	// standard input and have no flag for it — waybackurls is one — and this is the
	// alternative to reintroducing a shell just to write `printf ... |`.
	Stdin io.Reader
	// Dir, when set, is the working directory for the command. gowitness writes its
	// database relative to the process working directory, and the shell version had
	// to `cd` in a subshell to control where that landed.
	Dir string
	// DryRun records the command and returns success without executing it, which
	// is what makes the phase graph testable without a toolchain.
	DryRun bool
	// Optional commands report degradation without invalidating the phase.
	Optional          bool
	InterruptOnCancel bool // let bounded tools flush state before forced termination
	// OnResult receives every command outcome, including commands run by workers.
	// The pipeline uses it to keep a failed command from receiving a checkpoint.
	OnResult func(Result)

	mu       sync.Mutex
	executed []string
}

// Result is what a phase needs to know afterwards.
type Result struct {
	Cmd      []string
	ExitCode int
	Err      error
	LogPath  string
	Lines    int // lines the command wrote to stdout, when captured to a file
	Took     time.Duration
	TimedOut bool // a command budget expired; parent cancellation is different
	Optional bool
}

// Executed returns the commands this runner ran, in order, for tests and for the
// `--dry-run` transcript.
func (r *Runner) Executed() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.executed...)
}

func (r *Runner) record(cmd []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.executed = append(r.executed, formatCommand(cmd))
}

// Run executes cmd, writing stdout to outPath when it is non-empty and stderr to
// the step log either way. name is used for the log filename.
//
// Both streams are kept. Recon tools put their findings on stdout and their
// warnings — rate limiting, resolver failures, expired API keys — on stderr, and
// discarding stderr is how a run produces thirty results instead of three thousand
// and nobody notices why.
func (r *Runner) Run(ctx context.Context, name string, outPath string, cmd ...string) (res Result) {
	res.Cmd = cmd
	res.Optional = r.Optional
	started := time.Now()
	defer func() {
		res.Took = time.Since(started)
		if r.OnResult != nil {
			r.OnResult(res)
		}
	}()
	if len(cmd) == 0 {
		res.Err = errors.New("empty command")
		return res
	}
	r.record(cmd)
	if r.DryRun {
		return res
	}

	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}

	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	if r.InterruptOnCancel {
		c.Cancel = func() error { return c.Process.Signal(os.Interrupt) }
		c.WaitDelay = 5 * time.Second
	}
	c.Env = append(os.Environ(), r.Env...)
	if r.Stdin != nil {
		c.Stdin = r.Stdin
	}
	if r.Dir != "" {
		c.Dir = r.Dir
	}

	logPath, errLog, err := r.openLog(name, cmd)
	if err != nil {
		res.Err = err
		return res
	}
	defer errLog.Close()
	res.LogPath = logPath
	c.Stderr = errLog

	if outPath != "" {
		out, err := os.Create(outPath)
		if err != nil {
			res.Err = err
			return res
		}
		counted := &lineCounter{w: out}
		c.Stdout = counted
		err = c.Run()
		_ = out.Close()
		res.Lines = counted.n
		res.Err = err
	} else {
		c.Stdout = errLog
		res.Err = c.Run()
	}
	res.ExitCode = exitCode(res.Err, ctx)
	res.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	return res
}

// openLog creates the per-step log and writes the exact argv at the top of it. The
// argv is what makes a run reproducible: an operator can copy the line out of the
// log and re-run it by hand, which is the first thing anybody does when a phase
// returns something surprising.
func (r *Runner) openLog(name string, cmd []string) (string, *os.File, error) {
	if r.LogDir == "" {
		return "", nil, errors.New("runner has no log directory")
	}
	if err := os.MkdirAll(r.LogDir, 0o755); err != nil {
		return "", nil, err
	}
	path := fmt.Sprintf("%s/%s.log", strings.TrimRight(r.LogDir, "/"), safeName(name))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", nil, err
	}
	fmt.Fprintf(f, "# %s\n# %s\n\n", time.Now().Format(time.RFC3339), formatCommand(cmd))
	return path, f, nil
}

func safeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "step"
	}
	return b.String()
}

// exitCode separates the three outcomes a phase treats differently: the tool ran
// and reported failure, the tool could not be started, and the tool was still
// running when its deadline passed.
func exitCode(err error, ctx context.Context) int {
	if err == nil {
		return 0
	}
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return 130
		}
		return 124 // the conventional timeout status, as used by timeout(1)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// formatCommand quotes argv for readable, copyable POSIX-shell transcripts.
// Execution still uses exec.CommandContext directly.
func formatCommand(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		if arg != "" && !strings.ContainsAny(arg, " \t\r\n'\"`$\\;&|<>()*?![]{}") {
			quoted[i] = arg
		} else {
			quoted[i] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
		}
	}
	return strings.Join(quoted, " ")
}

// lineCounter counts newlines on the way past so a phase can report how much a
// tool produced without reading the artifact back.
type lineCounter struct {
	w io.Writer
	n int
}

func (l *lineCounter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\n' {
			l.n++
		}
	}
	return l.w.Write(p)
}
