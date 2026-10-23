//go:build !linux

package check

import (
	"os"
	"syscall"
)

// openRegular without O_PATH: check, then open. Racy, but the agent only runs on Linux; this is for tests.
func openRegular(open func(flags int) (*os.File, error)) *os.File {
	f, err := open(os.O_RDONLY | syscall.O_NONBLOCK)
	if err != nil {
		return nil
	}
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil
	}
	return f
}
