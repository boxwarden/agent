package check

import (
	"bufio"
	"net"
	"strings"
	"testing"

	"github.com/d3f4u1t/heimdall-agent/finding"
)

func TestExposed(t *testing.T) {
	root := t.TempDir()
	// 0.0.0.0:6379 redis, [::]:6379 same redis, 0.0.0.0:55432 postgres published by Docker (custom proxy name) to container 5432,
	// 127.0.0.1:3306 mysql (fine), 0.0.0.0:443 https (not risky).
	write(t, root, "proc/net/tcp", tcpHeader+
		"0: 00000000:18EB 00000000:0000 0A\n"+
		"1: 00000000:D888 00000000:0000 0A\n"+
		"2: 0100007F:0CEA 00000000:0000 0A\n"+
		"3: 00000000:01BB 00000000:0000 0A\n")
	write(t, root, "proc/net/tcp6", tcpHeader+"0: 00000000000000000000000000000000:18EB 00000000000000000000000000000000:0000 0A\n")
	write(t, root, "proc/77/cmdline", strings.Join([]string{"/opt/orbstack-guest/pstub", "-proto", "tcp", "-host-ip", "0.0.0.0", "-host-port", "55432", "-container-ip", "172.17.0.2", "-container-port", "5432"}, "\x00")+"\x00")
	write(t, root, "etc/ufw/ufw.conf", "# comment\nENABLED=yes\n")

	probeRedis = func(addr string) bool { return addr == "127.0.0.1:6379" }
	defer func() { probeRedis = redisNoAuth }()

	got := map[string]finding.Finding{}
	for _, f := range exposed(root) {
		got[f.ID] = f
	}
	if len(got) != 2 {
		t.Fatalf("want redis and postgres only, got %v", got)
	}
	if r := got["exposed.redis"]; r.Severity != finding.Critical || !strings.Contains(r.Detail, "0.0.0.0:6379, [::]:6379") {
		t.Errorf("redis: %+v", r)
	}
	if p := got["exposed.postgres"]; p.Severity != finding.High || !strings.Contains(p.Detail, "ufw does NOT block") || !strings.Contains(p.Detail, "ufw is enabled") || !strings.Contains(p.Fix, `"127.0.0.1:55432:5432"`) || p.Title != "PostgreSQL is exposed on port 55432" {
		t.Errorf("postgres: %+v", p)
	}
}

func TestRedisNoAuth(t *testing.T) {
	for reply, want := range map[string]bool{"+PONG\r\n": true, "-NOAUTH Authentication required.\r\n": false} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			bufio.NewReader(c).ReadString('\n')
			c.Write([]byte(reply))
			c.Close()
		}()
		if got := redisNoAuth(ln.Addr().String()); got != want {
			t.Errorf("reply %q: got %v, want %v", reply, got, want)
		}
		ln.Close()
	}
	if redisNoAuth("127.0.0.1:1") {
		t.Error("closed port must not count as open redis")
	}
}
