// Package host is the Go counterpart of lib/compat.sh: everything that differs
// between operating systems lives here and nowhere else.
//
// The shell version existed because bash has no portable way to ask how much RAM
// a machine has, and because GNU and BSD userlands disagree about sort, sed, stat
// and date. Most of that problem disappears in Go — sorting, hashing, path
// resolution and text munging are in the standard library and behave identically
// everywhere, which is the single biggest reason to have a compiled orchestrator
// at all. What remains is a short list of genuine kernel differences.
package host

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Info is a snapshot of the machine, taken once at startup.
type Info struct {
	OS      string // "linux", "darwin"
	Arch    string // "amd64", "arm64"
	WSL     bool   // Linux kernel running under Windows Subsystem for Linux
	Cores   int
	RAMMB   int    // 0 when it could not be determined
	Scratch string // fast writable directory for intermediate files
	DiskMB  int    // free space where results are written, 0 when unknown
	GoBin   string // GOPATH/bin, added to PATH so freshly installed tools resolve
}

// Probe collects everything the pipeline needs to size itself. It never fails:
// an unknown value is reported as zero and callers fall back to a conservative
// default rather than refusing to run.
func Probe(outputDir string) Info {
	i := Info{
		OS:    runtime.GOOS,
		Arch:  runtime.GOARCH,
		Cores: runtime.NumCPU(),
	}
	i.RAMMB = ramMB()
	i.WSL = isWSL()
	i.Scratch = scratchDir()
	i.DiskMB = int(diskFreeMB(outputDir))
	i.GoBin = goBinDir()
	ensurePath(i.GoBin)
	return i
}

func (i Info) String() string {
	s := fmt.Sprintf("%s/%s", i.OS, i.Arch)
	if i.WSL {
		s += " (WSL)"
	}
	return s
}

// ramMB reads total physical memory. Linux exposes it as a file; macOS only
// through sysctl. Anywhere else returns 0, which callers read as "unknown" and
// answer by sizing concurrency from the core count instead.
func ramMB() int {
	switch runtime.GOOS {
	case "linux":
		f, err := os.Open("/proc/meminfo")
		if err != nil {
			return 0
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// MemTotal:       16324708 kB
			if !strings.HasPrefix(sc.Text(), "MemTotal:") {
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				return 0
			}
			kb, err := strconv.Atoi(fields[1])
			if err != nil {
				return 0
			}
			return kb / 1024
		}
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err != nil {
			return 0
		}
		b, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		if err != nil {
			return 0
		}
		return int(b / (1024 * 1024))
	}
	return 0
}

// isWSL matters for two reasons: raw sockets are unavailable so port scanning has
// to fall back to a connect scan, and writing results onto a /mnt/c path is slow
// enough that users think the tool has hung.
func isWSL() bool {
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(b)), "microsoft")
}

// scratchDir prefers tmpfs on Linux. The pipeline writes and re-reads candidate
// wordlists that can reach millions of lines, and doing that on a spinning disk
// or a network-backed VPS volume dominates the runtime of phases 2 and 4.
func scratchDir() string {
	if runtime.GOOS == "linux" {
		if free := diskFreeMB("/dev/shm"); free >= 512 {
			if d, err := os.MkdirTemp("/dev/shm", "leetenum-"); err == nil {
				_ = os.Remove(d)
				return "/dev/shm"
			}
		}
	}
	return os.TempDir()
}

func goBinDir() string {
	if out, err := exec.Command("go", "env", "GOBIN").Output(); err == nil {
		if d := strings.TrimSpace(string(out)); d != "" {
			return d
		}
	}
	if out, err := exec.Command("go", "env", "GOPATH").Output(); err == nil {
		if d := strings.TrimSpace(string(out)); d != "" {
			return filepath.Join(d, "bin")
		}
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, "go", "bin")
	}
	return ""
}

// ensurePath adds dir to this process's PATH if it is missing. The shell version
// of this was a real bug source: it exported PATH silently, so tools that had
// just been installed were found during the run and "missing" on the next login.
// Callers are expected to tell the user how to make it permanent.
func ensurePath(dir string) {
	if dir == "" {
		return
	}
	cur := os.Getenv("PATH")
	for _, p := range filepath.SplitList(cur) {
		if p == dir {
			return
		}
	}
	_ = os.Setenv("PATH", cur+string(os.PathListSeparator)+dir)
}

// Have reports whether an executable is on PATH.
func Have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Which returns the resolved path of an executable, or "" if absent.
func Which(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

// FindChrome locates a Chromium-family browser for the screenshot phase. Checked
// in preference order: an explicit override, then PATH, then the fixed locations
// macOS installers use, which are not on PATH by default.
func FindChrome() string {
	if p := os.Getenv("CHROME_PATH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	for _, n := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "brave-browser"} {
		if p := Which(n); p != "" {
			return p
		}
	}
	for _, p := range []string{
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ConfigDir and CacheDir follow the XDG layout on Linux and Go's platform
// defaults elsewhere, so a macOS install does not scatter dotfiles in $HOME.
func ConfigDir() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "leetsec")
	}
	return filepath.Join(d, "leetsec")
}

func CacheDir() string {
	d, err := os.UserCacheDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "leetsec")
	}
	return filepath.Join(d, "leetsec")
}
