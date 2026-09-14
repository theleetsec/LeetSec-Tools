package scan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/theleetsec/LeetSec-Tools/internal/host"
	"github.com/theleetsec/LeetSec-Tools/internal/ui"
)

// Wordlists are cached under the user's cache directory, not dumped in $HOME, and
// refreshed only when stale. Three properties matter more than they look:
//
//   - A failed download must never clobber a good cached copy. The shell version
//     redirected curl straight onto the destination, so a 503 from the CDN replaced
//     a working wordlist with an empty file and every DNS phase then returned
//     nothing, with no error anywhere.
//   - A missing resolver list is fatal to phases 2 through 4 and 8, so there is a
//     hardcoded fallback. Silently resolving against nothing looks exactly like a
//     target with no subdomains.
//   - Nothing here is required for the tool to start. An air-gapped or offline run
//     uses whatever is cached, says so, and continues.
type Wordlists struct {
	Dir       string
	Brute     string
	Perms     string
	Resolvers string
}

type asset struct {
	name    string
	file    string
	url     string
	maxAge  time.Duration
	purpose string
}

// Resolver lists rot fast — a dead resolver poisons every result that depends on it
// — so they are refreshed daily while the wordlists are monthly.
//
// The permutation list is deliberately not here. It used to be fetched from a third
// party's default branch, which now 404s, and unlike the resolver list it had no
// fallback: phase 4 was silently reduced to nothing on any host without a cached
// copy. It is the one asset small enough to carry in the source, and a fixed list
// keeps two runs a month apart comparable — the same argument that pins the tools.
func assets() []asset {
	return []asset{
		{"DNS wordlist", "dns-brute.txt",
			"https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt",
			30 * 24 * time.Hour, "brute force"},
		{"trusted resolvers", "resolvers.txt",
			"https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt",
			24 * time.Hour, "every DNS phase"},
	}
}

var fallbackResolvers = []byte("1.1.1.1\n8.8.8.8\n9.9.9.9\n8.8.4.4\n1.0.0.1\n")

// defaultPerms is the built-in permutation wordlist. It is byte-identical to the
// heredoc in lib/pipeline.sh, and a CI step diffs the two so they cannot drift —
// the whole point of shipping two implementations at one version is that they
// produce the same artifacts, and the permutation seed list decides what phase 4
// even looks for.
//
// Kept deliberately small. gotator's output grows multiplicatively with this list,
// so a 10k-word permutation list against a few thousand seeds produces a candidate
// set no resolver can chew through inside the phase budget.
var defaultPerms = []byte(`dev
development
test
testing
tst
qa
uat
stage
staging
stg
prod
production
prd
preprod
pre
sandbox
sbx
demo
poc
lab
local
int
internal
external
ext
corp
intranet
extranet
private
public
admin
administrator
manage
management
mgmt
console
panel
portal
dashboard
api
apis
api1
api2
apiv1
apiv2
v1
v2
v3
rest
graphql
grpc
gw
gateway
proxy
edge
origin
lb
cdn
static
assets
img
images
media
files
upload
uploads
download
downloads
docs
doc
wiki
support
help
status
health
metrics
monitor
monitoring
grafana
kibana
elastic
log
logs
syslog
db
database
sql
mysql
postgres
pg
mongo
redis
cache
queue
mq
kafka
broker
worker
job
jobs
cron
batch
etl
data
warehouse
analytics
report
reports
bi
auth
sso
oauth
oidc
idp
login
account
accounts
user
users
customer
customers
client
clients
partner
vendor
shop
store
cart
checkout
pay
payments
billing
invoice
crm
erp
hr
mail
smtp
imap
webmail
mx
ns
ns1
ns2
vpn
remote
rdp
ssh
sftp
ftp
git
gitlab
jenkins
ci
cd
build
builds
deploy
release
registry
artifacts
nexus
k8s
kube
docker
cloud
aws
s3
bucket
storage
backup
backups
bak
archive
old
legacy
deprecated
new
temp
tmp
www
www1
www2
web
web1
web2
app
app1
app2
apps
srv
server
host
node
node1
node2
primary
secondary
standby
failover
dr
mirror
main
1
2
3
01
02
`)

// PrepareWordlists resolves the cache, refreshes what is stale, and guarantees a
// usable resolver list. override, when set, replaces the brute-force wordlist and is
// never downloaded over — an operator who passes their own list means it.
func PrepareWordlists(ctx context.Context, con *ui.Console, override string, offline bool) (Wordlists, error) {
	dir := filepath.Join(host.CacheDir(), "wordlists")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Wordlists{}, err
	}
	w := Wordlists{
		Dir:       dir,
		Brute:     filepath.Join(dir, "dns-brute.txt"),
		Perms:     filepath.Join(dir, "permutations.txt"),
		Resolvers: filepath.Join(dir, "resolvers.txt"),
	}
	if override != "" {
		if !fileHasContent(override) {
			return w, fmt.Errorf("wordlist %s is missing or empty", override)
		}
		w.Brute = override
	}

	for _, a := range assets() {
		dest := filepath.Join(dir, a.file)
		if override != "" && a.file == "dns-brute.txt" {
			continue
		}
		if fresh(dest, a.maxAge) {
			continue
		}
		if offline {
			if !fileHasContent(dest) {
				con.Warn(fmt.Sprintf("No cached %s and running offline; %s will be limited", a.name, a.purpose))
			}
			continue
		}
		st := con.Start("Fetching " + a.name)
		n, err := download(ctx, a.url, dest)
		switch {
		case err == nil:
			st.OK(fmt.Sprintf("%d entries", n))
		case fileHasContent(dest):
			// The cached copy is still there because download writes to a temp file
			// and only renames on success.
			st.Skipped("using the cached copy")
		default:
			st.Failed(err.Error())
		}
	}

	if !fileHasContent(w.Resolvers) {
		con.Warn("No resolver list available; falling back to five public resolvers")
		if err := os.WriteFile(w.Resolvers, fallbackResolvers, 0o644); err != nil {
			return w, err
		}
	}

	// LEETENUM_PERM_WORDLIST is honoured for parity with the shell implementation.
	// A named-but-unusable list is a warning rather than an error: permutations are
	// an optional phase, so degrading to the built-in list beats refusing to scan.
	if p := os.Getenv("LEETENUM_PERM_WORDLIST"); p != "" {
		if fileHasContent(p) {
			w.Perms = p
		} else {
			con.Warn("LEETENUM_PERM_WORDLIST is missing or empty; using the built-in list")
		}
	}
	if !fileHasContent(w.Perms) {
		if err := os.WriteFile(w.Perms, defaultPerms, 0o644); err != nil {
			return w, err
		}
		con.Info(fmt.Sprintf("Using the built-in permutation wordlist (%d words)", CountLines(w.Perms)))
	}
	return w, nil
}

// fresh reports whether path exists, is non-empty, and is younger than maxAge.
func fresh(path string, maxAge time.Duration) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() == 0 {
		return false
	}
	return time.Since(fi.ModTime()) < maxAge
}

func fileHasContent(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Size() > 0
}

// download fetches url to dest via a temp file in the same directory, so dest is
// either the old content or the new content and never a truncated mix. It returns
// the number of lines written.
//
// An empty 200 response is treated as a failure: an empty wordlist is worse than no
// wordlist, because the phase that reads it appears to run and finds nothing.
func download(ctx context.Context, url, dest string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "LeetEnum")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s returned %s", url, resp.Status)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".dl-"+filepath.Base(dest)+"-")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	counted := &lineCounter{w: tmp}
	// 512 MiB ceiling: a compromised or wrong URL should not be able to fill the
	// disk of a machine that is midway through an engagement.
	if _, err := io.Copy(counted, io.LimitReader(resp.Body, 512<<20)); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	if counted.n == 0 {
		return 0, fmt.Errorf("%s returned no data", url)
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return 0, err
	}
	return counted.n, nil
}

// CountLines is used for the phase headers ("wordlist: 2,187,000 entries"), which is
// the number that tells an operator whether they are about to wait ten minutes or
// ten hours.
func CountLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	buf := make([]byte, 256*1024)
	n := 0
	for {
		read, err := f.Read(buf)
		for _, b := range buf[:read] {
			if b == '\n' {
				n++
			}
		}
		if err != nil {
			return n
		}
	}
}

// HeadLines copies the first n lines of src to dst, which is how the recursive and
// permutation phases stay inside their profile budget without processing a
// two-million-entry wordlist.
//
// It streams rather than loading src, because the machines that most need a capped
// wordlist are the ones that cannot afford to hold the uncapped one in memory.
func HeadLines(src, dst string, n int) (int, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return 0, err
	}
	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	w := bufio.NewWriter(out)

	written := 0
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() && (n <= 0 || written < n) {
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := w.WriteString(line + "\n"); err != nil {
			out.Close()
			return written, err
		}
		written++
	}
	if err := sc.Err(); err != nil {
		out.Close()
		return written, err
	}
	if err := w.Flush(); err != nil {
		out.Close()
		return written, err
	}
	return written, out.Close()
}
