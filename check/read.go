package check

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxRead caps any file the agent reads; the largest legit one is dpkg's status (a few MB).
const maxRead = 32 << 20

// readFile returns path under root, or "" if it isn't a readable regular file. Users and containers
// control some of these paths (~/.ssh/authorized_keys can be a symlink to anything), so the file is
// never opened for reading unless it is a regular file: opening /dev/watchdog reboots the host, a FIFO
// hangs the scan, /dev/zero eats memory. Reads stop at maxRead. Under a container's /proc/<pid>/root,
// os.Root keeps symlinks in the path from escaping onto the host.
func readFile(root, path string) string {
	path = strings.TrimLeft(path, "/") // os.Root takes relative paths only
	open := func(flags int) (*os.File, error) { return os.OpenFile(filepath.Join(root, path), flags, 0) }
	if root != "/" {
		r, err := os.OpenRoot(root)
		if err != nil {
			return ""
		}
		defer r.Close()
		// A container's files are the container's to forge: don't follow its symlinks at all
		// (os-release, the one usually linked, is also read from usr/lib/os-release).
		if info, err := r.Lstat(path); err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ""
		}
		open = func(flags int) (*os.File, error) { return r.OpenFile(path, flags, 0) }
	}
	f := openRegular(open)
	if f == nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, maxRead))
	return string(b)
}
