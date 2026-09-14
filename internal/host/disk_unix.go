//go:build unix

package host

import "syscall"

// diskFreeMB returns free space in MiB at path, or 0 if it cannot be determined.
//
// Statfs_t is spelled slightly differently on each unix — Bsize is int64 on Linux
// and uint32 on Darwin — so the conversion to uint64 is what makes one expression
// compile on both. Windows has no equivalent and does not need one: the supported
// Windows path is WSL2 or the container image, both of which are Linux.
func diskFreeMB(path string) uint64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	return (uint64(st.Bsize) * st.Bavail) / (1024 * 1024)
}
