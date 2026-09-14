package tools

import (
	"os"
	"strings"
	"testing"
)

// The pinned versions exist in two places: this package, which the compiled binary
// uses, and lib/deps.sh, which the shell pipeline and the Dockerfile read. Two
// copies of twelve pins is two copies that drift, and the failure mode is quiet —
// a container built from one and a laptop installed from the other produce
// different findings from the same command.
//
// Rather than generate one from the other and add a build step, this test asserts
// they agree. It runs on every push, which is soon enough.
func TestPinsMatchShellInventory(t *testing.T) {
	b, err := os.ReadFile("../../lib/deps.sh")
	if err != nil {
		t.Skipf("lib/deps.sh not readable from here (%v); nothing to compare", err)
	}

	shell := map[string][2]string{} // name -> {module, version}
	// Bounded to the DEPS_GO_TOOLS block rather than grepping the whole file: other
	// quoted lines in deps.sh contain `||`, and a looser match picked two shell
	// commands up as tools named "${LS_PKG_INSTALL} ...".
	inArray := false
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "DEPS_GO_TOOLS=("):
			inArray = true
			continue
		case inArray && trimmed == ")":
			inArray = false
			continue
		case !inArray:
			continue
		}
		if !strings.HasPrefix(trimmed, `"`) {
			continue
		}
		fields := strings.Split(strings.Trim(trimmed, `"`), "|")
		if len(fields) < 3 {
			t.Errorf("unparseable inventory line: %s", trimmed)
			continue
		}
		shell[fields[0]] = [2]string{fields[1], fields[2]}
	}
	if len(shell) == 0 {
		t.Fatal("parsed no tools out of lib/deps.sh; the inventory format changed")
	}
	if len(shell) != len(GoTools) {
		t.Errorf("lib/deps.sh lists %d tools, this package lists %d", len(shell), len(GoTools))
	}
	for _, got := range GoTools {
		want, ok := shell[got.Name]
		if !ok {
			t.Errorf("%s is pinned here but absent from lib/deps.sh", got.Name)
			continue
		}
		if want[0] != got.Module {
			t.Errorf("%s module: shell has %q, Go has %q", got.Name, want[0], got.Module)
		}
		if want[1] != got.Version {
			t.Errorf("%s version: shell has %q, Go has %q", got.Name, want[1], got.Version)
		}
	}
}

// DEPS_REQUIRED in the shell is (subfinder puredns httpx). The Required flags here
// have to say the same thing, or `doctor` gates differently depending on which
// implementation the operator installed.
func TestRequiredSetMatchesShell(t *testing.T) {
	b, err := os.ReadFile("../../lib/deps.sh")
	if err != nil {
		t.Skipf("lib/deps.sh not readable from here (%v)", err)
	}
	var want []string
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "DEPS_REQUIRED=") {
			continue
		}
		inner := line[strings.Index(line, "(")+1 : strings.LastIndex(line, ")")]
		want = strings.Fields(inner)
	}
	if len(want) == 0 {
		t.Fatal("could not find DEPS_REQUIRED in lib/deps.sh")
	}
	got := map[string]bool{}
	for _, tl := range GoTools {
		if tl.Required {
			got[tl.Name] = true
		}
	}
	if len(got) != len(want) {
		t.Errorf("shell requires %v, Go requires %d tools", want, len(got))
	}
	for _, n := range want {
		if !got[n] {
			t.Errorf("%s is required by the shell inventory but optional here", n)
		}
	}
}
