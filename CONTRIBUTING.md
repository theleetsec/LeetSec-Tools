# Contributing to LeetEnum

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
