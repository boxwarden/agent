package check

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/boxwarden/agent/finding"
)

// Stratum ports public mining pools listen on. A miner renamed to look harmless, with its pool in a
// config file instead of argv, still has to connect to one.
var poolPorts = map[string]bool{"3333": true, "3334": true, "3357": true, "14433": true, "14444": true, "45560": true, "45700": true}

// poolConnections looks at established TCP connections in every network namespace, containers included.
func poolConnections(root string) []finding.Finding {
	var fs []finding.Finding
	var owners map[string]string // socket inode -> pid, built only if something matches
	seenNS, seen := map[string]bool{}, map[string]bool{}
	entries, _ := os.ReadDir(filepath.Join(root, "proc"))
	for _, e := range entries {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		ns, err := os.Readlink(filepath.Join(root, "proc", pid, "ns/net"))
		if err != nil {
			ns = pid
		}
		if seenNS[ns] {
			continue
		}
		seenNS[ns] = true
		for _, proto := range []string{"tcp", "tcp6"} {
			for line := range strings.SplitSeq(readFile(root, "proc/"+pid+"/net/"+proto), "\n") {
				f := strings.Fields(line)
				if len(f) < 10 || f[3] != "01" {
					continue
				}
				remote := procAddr(f[2])
				host, port, _ := net.SplitHostPort(remote)
				if !poolPorts[port] || !publicIP(net.ParseIP(host)) || seen[remote] {
					continue
				}
				seen[remote] = true
				if owners == nil {
					owners = socketOwners(root)
				}
				who := "unknown process"
				if p := owners[f[9]]; p != "" {
					who = strings.TrimSpace(readFile(root, "proc/"+p+"/comm")) + " (PID " + p + ")"
				}
				fs = append(fs, finding.Finding{
					ID: "ioc.pool-connection", Severity: finding.High,
					Title:  "Connection to a mining pool port: " + who + " → " + remote,
					Detail: "Port " + port + " is where crypto-mining pools take connections (stratum). Miners are the most common payload after a break-in.",
					Fix:    "sudo ss -tnp dst " + remote + "   # find the process, then assume compromise if you didn't start it",
					Key:    "ioc.pool-connection|" + port,
				})
			}
		}
	}
	return fs
}
