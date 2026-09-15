// Package tools is the dependency inventory: what the pipeline calls, which module
// provides it, which version is pinned, and whether a run can produce anything
// without it.
//
// Versions are pinned rather than tracked. `@latest` for a security toolchain means
// an upstream push can change your findings overnight, two people on the same team
// get different results from the same command, and a client asking what produced a
// finding cannot be answered. The pins are the same ones lib/deps.sh uses, and a
// test in this package fails if the two ever drift.
package tools

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/theleetsec/LeetSec-Tools/internal/host"
)

type Tool struct {
	Name     string
	Module   string
	Version  string
	Role     string
	Required bool // a scan produces nothing useful without it
}

// GoTools mirrors DEPS_GO_TOOLS in lib/deps.sh, including the corrections that
// rewrite made: gotator's module is Josue87's, not the josderstad path that never
// existed, and amass v4 and nuclei v3 replace the retired v3 and v2 lines.
var GoTools = []Tool{
	{"massdns", "", "system", "DNS resolver backend", true},
	{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder", "v2.6.6", "passive enumeration", true},
	{"assetfinder", "github.com/tomnomnom/assetfinder", "v0.1.1", "passive enumeration", false},
	{"amass", "github.com/owasp-amass/amass/v4/...", "v4.2.0", "passive enumeration", false},
	{"puredns", "github.com/d3mondev/puredns/v2", "v2.1.1", "DNS resolution and brute force", true},
	{"gotator", "github.com/Josue87/gotator", "v1.0.1", "permutation generation", false},
	{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx", "v1.6.9", "HTTP probing", true},
	{"naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu", "v2.3.1", "port scanning", false},
	{"katana", "github.com/projectdiscovery/katana/cmd/katana", "v1.1.0", "crawling", false},
	{"nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei", "v3.3.5", "vulnerability scanning", false},
	{"gowitness", "github.com/sensepost/gowitness", "3.0.5", "screenshots", false},
	{"anew", "github.com/tomnomnom/anew", "v0.0.4", "deduplication", false},
	{"waybackurls", "github.com/tomnomnom/waybackurls", "v0.1.0", "archive mining", false},
	{"gau", "github.com/lc/gau/v2/cmd/gau", "v2.2.4", "URL archive mining", false},
	{"tlsx", "github.com/projectdiscovery/tlsx/cmd/tlsx", "v1.1.9", "TLS SAN/CN names", false},
	{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx", "v1.2.1", "candidate DNS recovery", true},
}

// Helpers are not Go programs and cannot be installed the same way. massdns is
// listed first because puredns is useless without it, and puredns is required —
// which makes massdns effectively required too, despite having no formula and no
// Debian package on macOS.
var Helpers = []string{"massdns", "jq", "git", "dig", "findomain"}

const GoMinVersion = "1.23.0"

// Status is one row of the environment report.
type Status struct {
	Tool      Tool
	Path      string
	Installed bool
}

// Inventory resolves every tool against PATH. Read-only: safe to run anywhere,
// including in CI as a gate.
func Inventory() []Status {
	out := make([]Status, 0, len(GoTools))
	for _, t := range GoTools {
		p := host.Which(t.Name)
		out = append(out, Status{Tool: t, Path: p, Installed: p != ""})
	}
	return out
}

// MissingRequired lists the required tools that are absent. A non-empty result is
// what makes `doctor` exit non-zero, so it can be used as a gate in someone else's
// pipeline.
func MissingRequired(inv []Status) []string {
	var out []string
	for _, s := range inv {
		if s.Tool.Required && !s.Installed {
			out = append(out, s.Tool.Name)
		}
	}
	return out
}

// MissingOptional lists absent optional tools. These do not stop a run; the phases
// that need them are skipped, and saying so is the point — the original tool
// skipped silently and looked as though it had scanned.
func MissingOptional(inv []Status) []string {
	var out []string
	for _, s := range inv {
		if !s.Tool.Required && !s.Installed {
			out = append(out, s.Tool.Name)
		}
	}
	return out
}

// GoVersion returns the installed toolchain version, or "" if go is absent.
func GoVersion() string {
	out, err := exec.Command("go", "version").Output()
	if err != nil {
		return ""
	}
	// "go version go1.23.1 linux/arm64"
	f := strings.Fields(string(out))
	if len(f) < 3 {
		return ""
	}
	return strings.TrimPrefix(f[2], "go")
}

// Install fetches the Go tools with `go install module@version`.
//
// before and after are called around each tool so the caller can drive a progress
// display without this package importing the terminal layer. A failure on one tool
// does not abort the rest: an operator with eleven of twelve tools has a working
// pipeline, and stopping at the first network hiccup leaves them with nothing.
func Install(ctx context.Context, list []Tool, before func(Tool), after func(Tool, error)) []error {
	var errs []error
	if !host.Have("go") {
		return []error{fmt.Errorf("go toolchain not found; install Go %s or newer, or use the container image", GoMinVersion)}
	}
	for _, t := range list {
		if before != nil {
			before(t)
		}
		if t.Module == "" {
			if after != nil {
				after(t, nil)
			}
			continue
		}
		ref := t.Module + "@" + t.Version
		cmd := exec.CommandContext(ctx, "go", "install", ref)
		// GOFLAGS=-trimpath keeps absolute build paths out of the binaries, which
		// otherwise leak the operator's home directory into anything that prints a
		// stack trace on a client's machine.
		cmd.Env = append(cmd.Environ(), "GOFLAGS=-trimpath", "CGO_ENABLED=1")
		outErr, err := cmd.CombinedOutput()
		if err != nil {
			err = fmt.Errorf("%s: %w: %s", t.Name, err, lastLine(string(outErr)))
			errs = append(errs, err)
		}
		if after != nil {
			after(t, err)
		}
	}
	return errs
}

// MassdnsHint is what to tell an operator who is missing massdns, which has no Go
// port, no Homebrew formula, and no Debian package on macOS. Phases 2 through 4
// return nothing without it.
func MassdnsHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "git clone --depth 1 https://github.com/blechschmidt/massdns && make -C massdns && sudo install massdns/bin/massdns /usr/local/bin"
	default:
		return "apt-get install massdns, or build it: git clone --depth 1 https://github.com/blechschmidt/massdns && make -C massdns"
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[len(lines)-1])
}
