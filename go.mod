// Standard library only, deliberately.
//
// A recon tool that runs against other people's infrastructure is a bad place to
// carry a dependency tree: every module in it is code that ships to an operator's
// laptop and gets run against a client's assets. With no `require` block this
// builds air-gapped, `go build ./...` needs no proxy, and there is no supply
// chain to audit beyond the Go toolchain itself.
//
// It also means no cobra, no lipgloss, no termenv. The CLI is a switch statement
// and the terminal styling is a handful of escape sequences in internal/ui,
// which is all a ten-phase pipeline actually needs.
module github.com/theleetsec/LeetSec-Tools

go 1.21
