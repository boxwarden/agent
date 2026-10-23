package check

import (
	"syscall"

	"github.com/boxwarden/agent/finding"
)

func statfs(path string) (finding.Disk, bool) {
	var s syscall.Statfs_t
	if syscall.Statfs(path, &s) != nil {
		return finding.Disk{}, false
	}
	bs := uint64(s.Bsize)
	return finding.Disk{Size: s.Blocks * bs, Avail: s.Bavail * bs, Inodes: s.Files, InodesFree: s.Ffree}, true
}
