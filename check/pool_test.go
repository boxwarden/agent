package check

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPoolConnections(t *testing.T) {
	root := t.TempDir()
	// Established to 203.203.113.9:3333 by PID 20; to 10.0.0.9:3333, a private service; LISTEN on 3333.
	write(t, root, "proc/20/net/tcp", tcpHeader+
		"0: 0500000A:C822 0971CBCB:0D05 01 0 0 0 0 0 555 1\n"+
		"1: 0500000A:C823 0900000A:0D05 01 0 0 0 0 0 556 1\n"+
		"2: 00000000:0D05 00000000:0000 0A 0 0 0 0 0 557 1\n")
	write(t, root, "proc/20/comm", "kswapd-helper\n")
	os.MkdirAll(filepath.Join(root, "proc/20/fd"), 0o755)
	os.Symlink("socket:[555]", filepath.Join(root, "proc/20/fd/7"))

	fs := poolConnections(root)
	if len(fs) != 1 || fs[0].Title != "Connection to a mining pool port: kswapd-helper (PID 20) → 203.203.113.9:3333" {
		t.Errorf("got %+v", fs)
	}
}
