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

func TestOrchestratorPortsStayOutOfBaseline(t *testing.T) {
	root := t.TempDir()
	hexID := strings.Repeat("ab", 32)    // host-network container, known to Docker
	bridgeID := strings.Repeat("cd", 32) // bridge container, known to Docker
	ghostID := strings.Repeat("ef", 32)  // not in /var/lib/docker/containers
	row := func(n, addr, inode string) string {
		return n + ": " + addr + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 " + inode + " 1\n"
	}
	proc := func(pid, uid, exe, cgroup, inode string) {
		write(t, root, "proc/"+pid+"/cgroup", cgroup)
		write(t, root, "proc/"+pid+"/status", "Name:\tx\nUid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid+"\n")
		os.Symlink(exe, filepath.Join(root, "proc", pid, "exe"))
		if inode != "" {
			os.MkdirAll(filepath.Join(root, "proc", pid, "fd"), 0o755)
			os.Symlink("socket:["+inode+"]", filepath.Join(root, "proc", pid, "fd", "3"))
		}
	}
	write(t, root, "var/lib/docker/containers/"+hexID+"/hostconfig.json", `{"NetworkMode":"host"}`)
	write(t, root, "var/lib/docker/containers/"+bridgeID+"/hostconfig.json", `{"NetworkMode":"bridge","PortBindings":{"80/tcp":[{"HostIp":"10.114.112.16","HostPort":"24727"}]}}`)
	nomad := `{"Config":{"Labels":{"com.hashicorp.nomad.alloc_id":"2e3888c4"}}}`
	write(t, root, "var/lib/docker/containers/"+hexID+"/config.v2.json", nomad)
	write(t, root, "var/lib/docker/containers/"+bridgeID+"/config.v2.json", nomad)
	// Started by a docker-group user, not by Nomad: no label.
	plainHost, plainBridge := strings.Repeat("12", 32), strings.Repeat("34", 32)
	write(t, root, "var/lib/docker/containers/"+plainHost+"/config.v2.json", `{"Config":{"Labels":{}}}`)
	write(t, root, "var/lib/docker/containers/"+plainHost+"/hostconfig.json", `{"NetworkMode":"host"}`)
	write(t, root, "var/lib/docker/containers/"+plainBridge+"/config.v2.json", `{"Config":{}}`)
	write(t, root, "var/lib/docker/containers/"+plainBridge+"/hostconfig.json", `{"NetworkMode":"bridge","PortBindings":{"22/tcp":[{"HostIp":"","HostPort":"2222"}]}}`)
	sys := "0::/system.slice/docker.service\n"
	ctr := func(id string) string { return "0::/system.slice/docker-" + id + ".scope\n" }
	proc("10", "0", "/usr/local/bin/nomad", "0::/system.slice/nomad.service\n", "")
	proc("20", "0", "/usr/bin/docker-proxy", sys, "2001")                                                                              // published, in PortBindings
	proc("21", "0", "/usr/bin/docker-proxy", "0::/system.slice/evil.service\n", "2002")                                                // wrong cgroup
	proc("22", "0", "/tmp/docker-proxy", sys, "2003")                                                                                  // wrong exe path
	proc("23", "0", "/app/server", ctr(hexID), "2004")                                                                                 // host-network task in range
	proc("24", "0", "/app/server", ctr(hexID), "2005")                                                                                 // host-network, outside the range
	proc("25", "0", "/usr/bin/docker-proxy", ctr(bridgeID), "2006")                                                                    // forged path inside a container
	proc("26", "0", "/usr/sbin/sshd", "0::/system.slice/ssh.service\n", "2007")                                                        // someone else on a dynamic port
	proc("27", "1000", "/usr/bin/docker-proxy", "0::/user.slice/user-1000.slice/user@1000.service/app.slice/docker.service\n", "2008") // systemd-run --user --unit=docker.service
	proc("28", "1000", "/usr/bin/docker-proxy", sys, "2009")                                                                           // same, but pretending a root cgroup
	proc("29", "1000", "/tmp/backdoor", "0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-"+hexID+".scope\n", "2010")    // user scope named with 64 hex
	proc("30", "0", "/app/server", ctr(ghostID), "2011")                                                                               // container id Docker doesn't know
	proc("31", "0", "/app/server", ctr(bridgeID), "2012")                                                                              // bridge container: not host network
	proc("32", "0", "/usr/bin/docker-proxy", sys, "2013")                                                                              // port not in any PortBindings
	proc("33", "0", "/app/backdoor", ctr(plainHost), "2014")                                                                           // docker run --network host, in the range
	proc("34", "0", "/usr/bin/docker-proxy", sys, "2015")                                                                              // docker run -p 2222:22
	write(t, root, "proc/net/tcp", tcpHeader+
		row("0", "1070720A:6097", "2001")+ // 10.114.112.16:24727 docker-proxy
		row("1", "0100007F:6098", "2002")+ // 127.0.0.1:24728
		row("2", "0100007F:6099", "2003")+ // 127.0.0.1:24729
		row("3", "1070720A:609A", "2004")+ // 10.114.112.16:24730 host-network task
		row("4", "0100007F:1F90", "2005")+ // 127.0.0.1:8080
		row("5", "0100007F:1F91", "2006")+ // 127.0.0.1:8081
		row("6", "0100007F:609C", "2007")+ // 127.0.0.1:24732
		row("7", "0100007F:609D", "9999")+ // owner unknown, 127.0.0.1:24733
		row("9", "0100007F:609E", "2009")+ // 127.0.0.1:24734
		row("A", "0100007F:609F", "2010")+ // 127.0.0.1:24735
		row("B", "0100007F:60A0", "2011")+ // 127.0.0.1:24736
		row("C", "0100007F:60A1", "2012")+ // 127.0.0.1:24737
		row("D", "0100007F:60A2", "2013")+ // 127.0.0.1:24738
		row("E", "0100007F:60A3", "2014")+ // 127.0.0.1:24739
		row("F", "00000000:08AE", "2015")) // 0.0.0.0:2222
	got := Collect(root)["port"]
	for _, a := range []string{"10.114.112.16:24727", "10.114.112.16:24730"} {
		if _, ok := got["tcp "+a]; ok {
			t.Errorf("orchestrator port %s must not be in the baseline", a)
		}
	}
	for _, a := range []string{"127.0.0.1:24728", "127.0.0.1:24729", "127.0.0.1:8080", "127.0.0.1:8081", "127.0.0.1:24732", "127.0.0.1:24733",
		"127.0.0.1:24734", "127.0.0.1:24735", "127.0.0.1:24736", "127.0.0.1:24737", "127.0.0.1:24738", "127.0.0.1:24739", "0.0.0.0:2222"} {
		if _, ok := got["tcp "+a]; !ok {
			t.Errorf("%s must still alert", a)
		}
	}

	// Without a Nomad agent, a host-network container's port in the range is not excused.
	os.Remove(filepath.Join(root, "proc/10/exe"))
	if _, ok := Collect(root)["port"]["tcp 10.114.112.16:24730"]; !ok {
		t.Error("container port without nomad must alert")
	}
}
