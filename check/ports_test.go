package check

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInventory(t *testing.T) {
	root := t.TempDir()
	// Columns as in /proc/net/tcp; field 9 is the socket inode.
	row := func(n, addr, inode string) string {
		return n + ": " + addr + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 " + inode + " 1\n"
	}
	write(t, root, "proc/net/tcp", tcpHeader+
		row("0", "00000000:0016", "1001")+ // 0.0.0.0:22 sshd
		row("1", "00000000:D888", "1002")+ // 0.0.0.0:55432 docker-proxy -> postgres
		row("2", "0100007F:0CEA", "1003")) // 127.0.0.1:3306 mysql inside a container
	write(t, root, "proc/net/tcp6", tcpHeader+row("0", "00000000000000000000000000000000:24E3", "1004")) // [::]:9443 swarm ingress (dockerd)

	cid := strings.Repeat("ef", 32)
	procs := map[string]struct{ comm, cgroup, inode string }{
		"10":  {"sshd", "0::/system.slice/ssh.service\n", "1001"},
		"20":  {"docker-proxy", "0::/system.slice/docker.service\n", "1002"},
		"30":  {"mysqld", "0::/system.slice/docker-" + cid + ".scope\n", "1003"},
		"40":  {"dockerd", "0::/system.slice/docker.service\n", "1004"},
		"999": {"bash", "0::/user.slice/user-0.slice/session-1.scope\n", ""},
	}
	for pid, p := range procs {
		write(t, root, "proc/"+pid+"/comm", p.comm+"\n")
		write(t, root, "proc/"+pid+"/cgroup", p.cgroup)
		if p.inode != "" {
			os.MkdirAll(filepath.Join(root, "proc", pid, "fd"), 0o755)
			if err := os.Symlink("socket:["+p.inode+"]", filepath.Join(root, "proc", pid, "fd", "3")); err != nil {
				t.Fatal(err)
			}
		}
	}

	stopDocker := fakeDocker(t, map[string]string{
		"/containers/json": `[
			{"Id":"` + cid + `","Names":["/app-mysql-1"],"Image":"mysql:8","Ports":[{"PrivatePort":3306,"Type":"tcp"}]},
			{"Id":"aaaa","Names":["/app-db-1"],"Image":"postgres:16","Ports":[{"IP":"0.0.0.0","PrivatePort":5432,"PublicPort":55432,"Type":"tcp"}]}]`,
		"/services": `[{"Spec":{"Name":"portainer_portainer","TaskTemplate":{"ContainerSpec":{"Image":"portainer/portainer-ce:2.19"}}},
			"Endpoint":{"Ports":[{"Protocol":"tcp","TargetPort":9443,"PublishedPort":9443}]}}]`,
	})
	defer stopDocker()

	got := map[string]Port{}
	for _, p := range inventory(root, false) {
		got[p.Addr] = p
	}
	want := map[string]struct {
		owner       string
		public      bool
		servicePort int
	}{
		"0.0.0.0:22":     {"sshd (ssh.service)", true, 22},
		"0.0.0.0:55432":  {"docker app-db-1 [postgres:16]", true, 5432},
		"127.0.0.1:3306": {"container app-mysql-1 [mysql:8]", false, 3306},
		"[::]:9443":      {"swarm portainer_portainer [portainer/portainer-ce:2.19]", true, 9443},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for addr, w := range want {
		p := got[addr]
		if p.Owner() != w.owner || p.Public != w.public || p.ServicePort != w.servicePort {
			t.Errorf("%s: owner %q public %v servicePort %d; want %+v", addr, p.Owner(), p.Public, p.ServicePort, w)
		}
	}
	if r := got["[::]:9443"].Risk(); r != "high: Portainer admin panel" {
		t.Errorf("portainer risk from image: %q", r)
	}
}

// fakeDocker serves canned Docker API responses on a unix socket and points dockerSock at it.
func fakeDocker(t *testing.T, routes map[string]string) func() {
	t.Helper()
	dir, err := os.MkdirTemp("", "hd") // short path: unix socket paths are limited to ~104 bytes
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("agent sent %s %s: it must be read-only", r.Method, r.URL.Path)
		}
		if body, ok := routes[r.URL.Path]; ok {
			w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	})}
	go srv.Serve(ln)
	old := dockerSock
	dockerSock = sock
	return func() { dockerSock = old; srv.Close(); os.RemoveAll(dir) }
}

func TestDockerAllowlist(t *testing.T) {
	var out any
	if err := dockerGet("/containers/abc/exec", &out); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("non-allowlisted path must be refused, got %v", err)
	}
}

func TestFingerprint(t *testing.T) {
	ssh, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ssh.Close()
	go func() {
		for {
			c, err := ssh.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"))
			c.Close()
		}
	}()

	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Write([]byte("<html><head><title>\n  Portainer\n</title></head></html>"))
	})
	tlsSrv := httptest.NewTLSServer(page)
	defer tlsSrv.Close()
	plain := httptest.NewServer(page)
	defer plain.Close()

	silent, _ := net.Listen("tcp", "127.0.0.1:0") // accepts, says nothing, not HTTP
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 1)
			c.Read(buf) // hold until the client gives up
			c.Close()
		}
	}()

	for addr, want := range map[string]string{
		ssh.Addr().String():                        "ssh SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
		strings.TrimPrefix(tlsSrv.URL, "https://"): `https 200 "Portainer" server=nginx`,
		strings.TrimPrefix(plain.URL, "http://"):   `http 200 "Portainer" server=nginx`,
		silent.Addr().String():                     "unknown (no banner, not HTTP)",
	} {
		if got := fingerprint(addr); got != want {
			t.Errorf("%s: got %q, want %q", addr, got, want)
		}
	}
}
