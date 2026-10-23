# Contributing to LeetEnum

## Your first pull request

New here? Start with an issue labelled [`good first issue`](https://github.com/theleetsec/LeetSec-Tools/labels/good%20first%20issue). Each one names the files to touch, the test to add, and the command that proves it works. Most take under an hour.

1. Comment on the issue so nobody else picks the same one.
2. Fork the repo and create a branch: `git checkout -b fix/short-name`.
3. Make the change. For Go code, add or update a `_test.go` file next to it.
4. Run the checks below. They need no network access and no recon tools installed.
5. Open the pull request and fill in the template.

A maintainer will review within a week. If something needs changing, we'll say exactly what. Every merged contributor is thanked by name in the release notes.

Stuck? Ask on the issue. Questions are welcome, that's what the label is for.

## General guidelines

Contributions are welcome. Please open an issue before a large change so its scope and compatibility impact are clear.

LeetEnum has Bash and Go implementations. Keep phase names, artifact names, scope filtering, and safety behavior aligned where they overlap. Do not add credentials, target data, generated scan directories, or personal paths to commits.

Run these checks before opening a pull request:

```sh
bash tests/run.sh
go test -race -count=1 ./...
go vet ./...
```

Format Go code with `gofmt`. Shell changes must work with Bash 3.2 on macOS and use the portability helpers in `lib/compat.sh`. New external tools need a pinned version, documentation, fixture coverage, and a reason they cannot be optional.

Describe user-visible behavior, safety or scope implications, and tests in each pull request. Never include live reconnaissance output. Only run LeetEnum against systems you own or have explicit written authorization to test.
