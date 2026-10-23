package check

import (
	"io/fs"
	"strings"
	"syscall"
)

var rootUID = 0 // swapped in tests, which can't create root-owned files

// ownerUID is the file's owner, or -1 when the platform doesn't say.
func ownerUID(info fs.FileInfo) int {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

// shQuote makes a user-controlled string (a file name) safe to paste into a shell command.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
