## What this changes

<!-- One or two sentences. Link the issue: "Closes #123". -->

## Why

<!-- The problem this fixes or the gap it fills. -->

## How I tested it

<!-- Paste the commands you ran and say whether they passed. -->

- [ ] `bash tests/run.sh`
- [ ] `go test -race -count=1 ./...`
- [ ] `go vet ./...`
- [ ] `gofmt -l .` prints nothing

## Checklist

- [ ] No credentials, target data, scan output or personal paths in the diff
- [ ] Shell changes work on Bash 3.2 (macOS) and use `lib/compat.sh` helpers
- [ ] No new editor auto-run tasks (`.vscode/tasks.json`) or build hooks
- [ ] User-visible behaviour change is noted in `CHANGELOG.md` (skip for tests and docs only)
