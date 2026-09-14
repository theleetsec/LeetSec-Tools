//go:build !unix

package host

// Non-unix build: free space is reported as unknown rather than guessed. The
// callers treat 0 as "do not warn", which is the right behaviour — a spurious
// low-disk warning on a platform we do not measure is worse than no warning.
func diskFreeMB(string) uint64 { return 0 }
