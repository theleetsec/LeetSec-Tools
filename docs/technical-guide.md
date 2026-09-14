# LeetEnum v1 technical guide

LeetEnum orchestrates external reconnaissance tools through nine phases. The Bash
entry point is `leetenum.sh`; the standard-library-only Go orchestrator is under
`cmd/leetenum` and `internal/scan`.

Phases are passive intelligence, DNS brute force, recursive brute force, gotator
permutations, HTTP probing, port scanning, crawling and archived URLs, vulnerability
scanning, and screenshots. Durable artifacts live in timestamped
`recon_<domain>/` runs. Required tool failures leave checkpoints incomplete so a
rerun can retry them; optional source failures are logged as warnings.

The former dedicated takeover phase is absent. General Nuclei scans exclude templates
tagged `takeover`.

`--only` reruns selected phases. When the latest run is complete, LeetEnum seeds a new
run from its saved inputs and preserves the completed run as the differential baseline.
Go `--dry-run` prints planned commands using placeholders and does not create or alter
scan state. `--offline` only disables wordlist refresh; it does not make a live scan
offline.

Profiles auto-tune DNS rate, HTTP concurrency, recursive workers, port rate, and input
limits from CPU and RAM. `doctor` reports external dependencies; `install` uses pinned
versions. Run logs record command arguments and phase state for reproducibility.

Tests use local fixtures and temporary directories. They cover scope filtering, resume,
selected phases, failure handling, dry-run isolation, and shell portability. They do
not measure real discovery completeness or third-party service uptime.
