# LeetEnum v1.1.0

[![CI](https://github.com/theleetsec/LeetSec-Tools/actions/workflows/ci.yml/badge.svg)](https://github.com/theleetsec/LeetSec-Tools/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/theleetsec/LeetSec-Tools?sort=semver)](https://github.com/theleetsec/LeetSec-Tools/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/theleetsec/LeetSec-Tools)](https://github.com/theleetsec/LeetSec-Tools/stargazers)

Reconnaissance pipeline for authorised security assessments, by LeetSecurity LLC.

This is the actively maintained v1 line. The existing repository is preserved so
its community stars and forks remain attached to the project.

## Features

- 12+ passive discovery sources, including nine public HTTP APIs that run in
  parallel, plus DNS records, certificate names, and archive lookups
- Tiered DNS brute force, recursive brute force, and gotator permutations
- Resolver health checks, scope filtering, atomic artifacts, and resumable checkpoints
- RAM/CPU auto-tuning with `lite`, `balanced`, and `beast` profiles
- Structured JSONL HTTP and vulnerability output plus Markdown reports
- Nine phases, selected-phase reruns, differential reports, monitor mode, and a
  Bash 3.2 compatible implementation

The former dedicated subdomain takeover phase was removed. Nuclei is run with the
`takeover` template tag excluded.

## Daily use — subdomain hunt

```sh
leetenum example.com --subs
```

That is the one command. It runs every **free** source that actually finds names
(subfinder, assetfinder, amass, findomain if present, crt.sh, Wayback, HackerTarget,
RapidDNS, AlienVault OTX, Anubis, Cert Spotter, ThreatMiner, urlscan, DNS NS/MX/TXT/SPF,
AXFR, brute, recursive brute, permutations, HTTP, TLS SAN/CN, katana, waybackurls, gau)
then **deepens** one label further so `api.internal.staging.example.com` can appear
after `internal.staging.example.com` is known.

`--subs` skips ports, nuclei and screenshots. Drop it for the full nine-phase pipeline.

The live line while it works:

```
  leetenum  1.1.0   reconnaissance pipeline
  ·•◦•·•◦•·•◦•·•◦•
  ⠋ passive APIs (crt.sh, wayback, otx, …)  12s   names 1402  resolved 0  live 0
```

LeetEnum runs nine phases against one apex domain — passive intelligence, DNS brute
force, recursive brute force, permutations, HTTP probing, port
scanning, crawling, vulnerability scanning and screenshots — and writes a report you
can hand to a client. It orchestrates well-known tools (subfinder, puredns, httpx,
naabu, katana, nuclei and others) rather than reimplementing them, so the value is in
the sequencing, the scope discipline, the budgets and the fact that an interrupted
run resumes instead of starting over.

Only scan systems you are authorised to test. Every phase in this pipeline generates
traffic that is attributable to you.

See [docs/technical-guide.md](docs/technical-guide.md) for phase inputs, state
transitions, safety boundaries, and validation limits.

## Install

Four paths. Pick one; they all end up with `leetenum` on your `PATH`.

**Standalone binary** — no runtime, no dependencies, one file. Replace the platform
suffix with `linux_arm64`, `darwin_amd64` or `darwin_arm64` as needed.

```sh
v=1.1.0
curl -fsSLO "https://github.com/theleetsec/LeetSec-Tools/releases/download/v${v}/leetenum_${v}_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/theleetsec/LeetSec-Tools/releases/download/v${v}/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
# macOS: grep "_darwin_arm64.tar.gz$" SHA256SUMS | shasum -a 256 -c -
tar -xzf "leetenum_${v}_linux_amd64.tar.gz"
sudo install "leetenum_${v}_linux_amd64/leetenum" /usr/local/bin/
```

**One-line installer** — installs the shell implementation and then fetches the recon
toolchain for you.

```sh
curl -fsSL https://raw.githubusercontent.com/theleetsec/LeetSec-Tools/main/install.sh | sh
```

It takes `--prefix`, `--bin`, `--ref`, `--tarball` (for air-gapped hosts),
`--no-tools` and `--uninstall`. Read it before you pipe it to a shell; it is POSIX
`sh` on purpose and it is short.

**Homebrew**, on macOS or Linuxbrew:

```sh
brew tap theleetsec/tap
brew install leetenum
```

**Container**, which is also the supported way to run on Windows:

```sh
docker run --rm -v "$PWD:/work" ghcr.io/theleetsec/leetenum example.com
```

The `full` tag adds Chromium so phase 9 produces screenshots. Results land in the
current directory because `/work` is the image's working directory and its volume.

### Then the toolchain

The binary and the container are self-contained, but the recon tools themselves are
separate programs. Install them once:

```sh
leetenum install     # 12 pinned Go tools plus massdns
leetenum doctor      # what is present, what is missing, what this machine can do
```

`doctor` exits non-zero when a required tool is absent, so it works as a CI gate.
Optional tools are reported as optional and their phases degrade with a warning
rather than failing the run.

## Use

```sh
leetenum example.com --subs                       # all subdomain sources, then stop
leetenum example.com                              # everything, machine-sized
leetenum example.com --profile beast --deep       # more concurrency, low+info findings
leetenum scan -d example.com --only p5,p8         # re-probe and re-scan, nothing else
leetenum scan -d example.com --skip p6,p9         # no port scan, no screenshots
leetenum scan -f targets.txt -o ~/engagements     # a file of domains
leetenum scan -d example.com --monitor            # loop, report only what is new
leetenum example.com --dry-run                    # print the commands, run nothing
```

An interrupted scan resumes: run the same command again and it continues from the
phase it stopped in. `--fresh` starts over instead.

## Phases

| id | phase | tools | bounded at |
|----|-------|-------|-----------|
| p1 | Passive intel | subfinder, assetfinder, amass, crt.sh; dnsx recovery | amass 10m + export 2m |
| p2 | Brute force | puredns + massdns | — |
| p3 | Recursive brute force | puredns, per-parent worker pool | — |
| p4 | Permutations | gotator + puredns | gotator 30m |
| p5 | HTTP probing | httpx | — |
| p6 | Port scanning | naabu, then httpx on what it finds | — |
| p7 | Crawling | katana, waybackurls, gau; dnsx recovery | katana 45m–6h, archives 10m each |
| p8 | Vulnerability scan | nuclei | — |
| p9 | Screenshots | gowitness + Chromium | 30m |

Phases select each other's output from disk, not from memory, which is why `--only`
and resume produce the same results as a clean run. Phase 7 feeds hostnames back into
the master list: names that appear only in a JavaScript bundle, a CSP header or a
redirect chain are never seen by DNS enumeration.

The bounded phases exist because recon tools have no natural end. amass on a large
target and katana on a single-page app will both run until something stops them, and
hitting a budget retains partial output. Crawl budget exhaustion leaves phase 7
pending so saved work can be continued; optional source failures are recorded as
warnings and do not invalidate successful results from other sources.

### Collection reliability and exclusions

Amass v4/v5 discovery uses `amass enum -passive -d <domain> -nocolor`, followed by
`amass subs -names -d <domain> -nocolor`. Both use Amass's configured default
database. Amass v5 requires its separately configured collection engine and asset
database; leetenum does not start an engine or replace its configuration. The
enumeration transcript, exported names and per-command diagnostics are retained.
An unavailable engine, unsupported version or failed export produces an explicit
warning while the other sources continue.

Collected candidates are kept in `01_candidates.txt` and `07_candidates.txt`.
Bulk DNS resolution does not suppress wildcards or sanitize already validated
collected names. Misses receive an independent dnsx A/AAAA pass with 100 workers,
three retries and a rate capped at 500 queries/second. dnsx is a required dependency
for this recovery path. Remaining names are retained separately in
`01_unresolved.txt` and `07_unresolved.txt`; resolver failure keeps the phase pending
and preserves partial verified output. DNS availability can change, and shared
edge/wildcard answers do not establish distinct applications or ownership.

Use `--exclude-file exclusions.txt` in either implementation to omit collection
names before resolution and downstream use. The file accepts exact hostnames or
`*.suffix` patterns, one per line, with blank lines and `#` comments:

```text
# Illustrative customer namespace, not a built-in target policy
*.mx.saas.example.com
unwanted.example.com
```

The wildcard excludes descendants such as `customer.mx.saas.example.com` while
preserving `mx.saas.example.com`. Exact patterns exclude only that name. Matching
is case-insensitive and respects label boundaries. These are opt-in collection
filters; ownership verification and program scope decisions remain separate.
The filters also apply to names reintroduced by TLS, archives, crawling and master
rebuilding. Normalized patterns are saved in `collection-exclusions.txt`; resume
requires the same patterns, or `--fresh` for a new run. Raw tool diagnostics may
contain excluded input as provenance and are not collection master lists.

### Continuing a truncated crawl

Katana's default wall-clock budget is 45 minutes per started block of 1,000 live
seed URLs, capped at six hours. `--crawl-budget 2h` overrides the Katana budget and
each archive source's default 10-minute budget. Both implementations
accept positive whole seconds, minutes or hours (e.g. `2700`, `45m`, `2h`), up to
168 hours. Existing crawl depth, concurrency and request-rate limits are unchanged.

```sh
leetenum example.com --resume-crawl --crawl-budget 2h --exclude-file exclusions.txt
bash leetenum.sh example.com --resume-crawl --crawl-budget 2h --exclude-file exclusions.txt
```

`--resume-crawl` selects only phase 7. Completed batches of at most 100 seeds and
completed archive sources are skipped. Partial URLs are merged with prior output;
the unfinished batch is retried. It is continuation at the seed-batch level, not a
checkpoint of every crawler request. An unfinished archive query is replayed and
deduplicated because its external CLI has no portable cursor. Pending sources are
listed in `07_crawl_pending.txt`. A regular interrupted run also uses saved progress;
explicit `--only p7` without `--resume-crawl` restarts the crawl work. `--fresh` starts
a new run and cannot be combined with `--resume-crawl`.

## Profiles

`--profile auto` is the default and sizes the run from the machine's cores and memory.
Force one when you know better.

| profile | picked when | DNS/s | httpx threads | recursion fanout | naabu/s |
|---------|-------------|-------|---------------|------------------|---------|
| lite | anything smaller | 1000 | 40 | 2 | 500 |
| balanced | ≥ 7 GB RAM and ≥ 4 cores | 5000 | 120 | cores | 1500 |
| beast | ≥ 32 GB RAM and ≥ 8 cores | 15000 | 300 | cores × 2 | 3000 |

The DNS rate is a total, not a per-worker figure: it is divided by the fanout before
the workers start, with a floor of 50/s each. Multiplying instead of dividing is how
the original saturated its resolvers, and a resolver dropping queries looks exactly
like a target with no subdomains.

## Output

```
recon_example.com/
├── latest -> 20260901_140322          symlink, or latest.txt where symlinks fail
└── 20260901_140322/
    ├── 01_passive.txt   02_brute.txt   03_recursive.txt   04_perms.txt
    ├── 05_live_urls.txt 05_http.jsonl  06_ports.txt       06_extra_urls.txt
    ├── 07_urls.txt      07_crawled_hosts.txt
    ├── master_dns.txt                 every in-scope hostname found
    ├── master_live_urls.txt           every live HTTP service
    ├── reports/
    │   ├── summary.md                 the file to read first
    │   ├── new_since_last_run.txt     differential against the last complete run
    │   ├── nuclei.txt   nuclei.jsonl
    │   └── screenshots/
    ├── logs/                          one log per tool, plus leetenum.log
    └── .state/                        phase checkpoints
```

Every artifact is lowercase, deduplicated, byte-sorted, and filtered to the target's
scope on the way in — a name a third-party source volunteered outside the engagement
cannot reach a client report, however it arrived. Writes are atomic, so a killed run
never leaves a half-written list. Empty and absent mean the same thing to every reader,
which is what lets a skipped phase leave downstream phases unchanged.

`logs/leetenum.log` is the terminal transcript with the colour stripped and timestamps
added. It is the file to attach to a report.

## Resume and differential reporting

A phase is marked complete only when it succeeds. Interrupt a run at hour six and the
five phases before it stay done; the phase that was in flight is retried. A run is
marked complete only when every phase was either run or deliberately skipped, and that
marker does two things: it stops the next invocation resuming into the directory, and
it makes the run eligible as a differential baseline.

`reports/new_since_last_run.txt` is this run's master list minus the newest previously
*completed* run's. Comparing against an incomplete run would report hosts as new
because the earlier run never got to them, so incomplete runs are never used as a
baseline. With `--monitor`, that file is the whole point: each pass reports only what
changed.

## Platforms

Linux and macOS are both first-class, on x86_64 and arm64. Windows is supported
through WSL2 or the container, which is a deliberate choice: serving Windows natively
would mean maintaining a second set of process and filesystem code for a platform where
most of the underlying recon tools are not tested anyway.

macOS is the harder target of the two and the shell implementation is written for it
specifically. `/bin/bash` on macOS is 3.2, so there are no associative arrays, no
`${var^^}`, no `mapfile`. The userland is BSD, so `sort --parallel`, `sed -i` without
an argument, `readlink -f`, `nproc`, `free`, `md5sum` and `timeout` are all either
absent or differently spelled. Every one of those goes through a shim in
`lib/compat.sh`, and CI fails the build if a bare call to any of them reappears at a
call site. `timeout` is the instructive one: it does not exist on macOS at all, so all
the bounded phases used to produce nothing there while reporting only that their tool
had failed. It is now a shell watchdog when no binary is available, and `leetenum
doctor` tells you which mechanism is in use.

Low-spec hosts are handled by the `lite` profile and by treating scratch space as an
optimisation. If there is no usable tmpfs, work goes into the run directory instead of
failing, and nothing a resume depends on is ever written to scratch.

## Two implementations

The repository contains both, at the same version, producing the same artifacts with
the same names.

`leetenum.sh` with `lib/` is the shell implementation: what the installer and the
Homebrew formula give you, and what the container runs. It additionally has `config`
for the notification wizard and `-y/--yes` for unattended runs.

`cmd/leetenum` with `internal/` is a Go rewrite of the same pipeline, and is what the
release tarballs contain. It is standard library only — no cobra, no lipgloss, and CI
enforces that the dependency tree stays empty — and it is built with `CGO_ENABLED=0`
so the binary is genuinely static. That is what makes "download one file and run it"
true rather than aspirational. It adds `--wordlist`, `--offline` and `--dry-run`, and
its `--interval` takes a duration (`90m`, `6h`) where the shell version takes seconds.

Either is a complete tool. The Go build exists for the install story; the shell build
exists because a pipeline of shell tools is easy to read, patch and audit on a host
you have just been given access to.

## Configuration

Nothing needs configuring to run a scan. Notifications and cached wordlists are the
only state, and both live under XDG paths.

| variable | effect |
|----------|--------|
| `LEETENUM_OUTPUT_DIR` | default output root |
| `LEETENUM_WORDLIST` | default DNS brute-force wordlist |
| `LEETENUM_PERM_WORDLIST` | permutation seed list, replacing the built-in one |
| `LEETENUM_CONFIG_DIR` | config location, default `$XDG_CONFIG_HOME/leetsec` |
| `LEETENUM_CACHE_DIR` | cache location, default `$XDG_CACHE_HOME/leetsec` |
| `LEETENUM_FORCE=1` | `install` reinstalls tools already present |
| `LEETENUM_UNPINNED=1` | `update` installs `@latest` instead of the pinned versions |
| `CHROME_PATH` | browser to use for screenshots |
| `NO_COLOR` | disable colour, as does `--no-color` |

Tool versions are pinned, and `update` reinstalls at those pins. `LEETENUM_UNPINNED=1`
exists for when you need a fix that is only on `main`, not as a default, because an
unpinned toolchain means two runs a week apart are not comparable.

The DNS wordlist and the resolver list are downloaded and cached — resolvers daily,
since a dead resolver poisons every result that depends on it, and the wordlist
monthly. The permutation seed list is not: it is built into both implementations, small
and deliberately so, because gotator's output grows multiplicatively with it. Point
`LEETENUM_PERM_WORDLIST` at your own file to replace it. A download that fails leaves
the cached copy in place rather than truncating it, and a run with no network uses
whatever is cached and says what it is missing.

Exit codes: 0 success, 1 error, 2 bad usage, 130 interrupted. A first Ctrl-C cancels
the run and leaves it resumable; a second exits immediately.

## How this is tested

```sh
bash tests/run.sh          # fixture suite, no network or recon tools required
```

The suite parses every shell file, unit-tests the portability shims, replays the
command-injection strings that reached `eval` in v1 against the target validator, and
then runs the whole pipeline against a stand-in toolchain to check the parts that are
easy to get wrong: that a resumed run loses no hosts and does not create a second
directory, that `--only` re-runs the phase you named and leaves the other checkpoints
alone, and that the differential excludes previously-known hosts. It also diffs the
built-in permutation wordlist against the Go copy of the same list, since the two
implementations ship at one version and are only the same tool if they enumerate the
same candidates.

CI runs it on ubuntu-latest, ubuntu-22.04, macos-14 (arm64) and macos-15-intel (x86_64), and
asserts on the macOS runners that it is testing the system `/bin/bash` 3.2 and the BSD
userland rather than quietly picking up Homebrew's bash and GNU coreutils — which would
make the whole macOS matrix meaningless. shellcheck runs at `-S warning` over the bash
sources and in `-s sh` mode over the installer. The Go side is gofmt-checked, vetted,
tested with `-race -count=1`, checked for an empty dependency tree, made to reject five
specific bad invocations, and then walked end to end under `--dry-run --offline` to
assert the artifact set, the plain-text transcript, and both halves of the resume
contract. The linux/amd64 release binary is checked with `file` for static linkage,
because a dynamically linked artifact would silently break the one-file install claim.

### What the tests do not cover

Worth knowing before you trust a green build.

The default suite uses stand-in recon tools. Every pipeline test uses a
stand-in toolchain or `--dry-run`, so what is verified is the orchestration — sequencing,
scope filtering, artifact handling, resume, budgets — and not the parsing of any real
tool's real output. A tool changing its output format is a class of breakage these
tests may not catch.

An optional installed-tool compatibility check uses a synthetic DNS server bound
only to loopback:

```sh
python3 tests/local-dns-check.py
```

It requires installed puredns, massdns and dnsx. It checks underscore-label
sanitization, AAAA-only records, and recovery of a simulated first-pass omission
using the real tool output formats. Logs are saved in a fresh temporary directory;
set `LEETENUM_TEST_OUTPUT_DIR` to choose a diagnostic directory. The default CI
suite remains offline and also compares Bash and Go recovery and crawl checkpoint
artifacts directly.

The container image and the Homebrew formula are built and installed only by CI on
release; neither has a test that runs on every commit. The installer's download path is
exercised against a local tarball rather than `codeload.github.com`, so a change in
GitHub's archive behaviour would not be caught until someone ran the one-liner. And
macOS bash 3.2 compatibility is enforced by the CI matrix, not by any local check — a
3.2-incompatible construct will not be noticed until CI runs it.

## License

MIT. Property of LeetSecurity LLC.

Use this only against systems you own or have written authorisation to test.
