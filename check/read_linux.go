package check

import (
	"os"
	"strconv"
	"syscall"
)

// oPath is O_PATH, which the frozen syscall package lacks on amd64. Same value on amd64 and arm64,
// the only architectures released.
const oPath = 0x200000

// openRegular resolves the path with O_PATH, which touches no device, checks that it ended at a
// regular file, and only then opens that same inode for reading through /proc/self/fd: no race.
func openRegular(open func(flags int) (*os.File, error)) *os.File {
	p, err := open(oPath | syscall.O_CLOEXEC)
	if err != nil {
		return nil
	}
	defer p.Close()
	if info, err := p.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil
	}
	f, err := os.OpenFile("/proc/self/fd/"+strconv.Itoa(int(p.Fd())), os.O_RDONLY|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	return f
}
