package check

import (
	"bufio"
	"net"
	"strings"
	"testing"

	"github.com/boxwarden/agent/finding"
)

func TestExposed(t *testing.T) {
	ports := []Port{
		{Addr: "0.0.0.0:6379", Port: 6379, Public: true, ServicePort: 6379, Process: "redis-server", Unit: "redis-server.service"},
		{Addr: "[::]:6379", Port: 6379, Public: true, ServicePort: 6379},
		{Addr: "0.0.0.0:55432", Port: 55432, Public: true, ServicePort: 5432, Published: "docker", Container: "app-db-1", Image: "postgres:16"},
		{Addr: "[::]:9443", Port: 9443, Public: true, ServicePort: 9443, Published: "swarm", Container: "portainer_portainer", Service: `https 200 "Portainer"`},
		{Addr: "127.0.0.1:3306", Port: 3306, Public: false, ServicePort: 3306},                                          // local only
		{Addr: "0.0.0.0:443", Port: 443, Public: true, ServicePort: 443, Image: "traefik:v3", Service: "https 404"},     // proxy, not a panel
		{Addr: "0.0.0.0:2377", Port: 2377, Public: true, ServicePort: 2377, Process: "dockerd", Unit: "docker.service"}, // swarm manager
	}
	probeRedis = func(addr string) bool { return addr == "127.0.0.1:6379" }
	defer func() { probeRedis = redisNoAuth }()

	got := map[string]finding.Finding{}
	for _, f := range exposed(ports, true) {
		got[f.ID] = f
	}
	if len(got) != 4 {
		t.Fatalf("want redis, postgres, portainer, swarm manager; got %v", got)
	}
	if r := got["exposed.redis"]; r.Severity != finding.Critical || !strings.Contains(r.Detail, "0.0.0.0:6379, [::]:6379 (redis-server (redis-server.service))") {
		t.Errorf("redis: %+v", r)
	}
	if p := got["exposed.postgres"]; p.Title != "PostgreSQL is exposed on port 55432" || !strings.Contains(p.Detail, "ufw does NOT block") ||
		!strings.Contains(p.Detail, "ufw is enabled") || !strings.Contains(p.Fix, `"127.0.0.1:55432:5432"`) {
		t.Errorf("postgres: %+v", p)
	}
	if a := got["exposed.admin-panel"]; a.Title != "Portainer admin panel is exposed on port 9443" || a.Severity != finding.High ||
		!strings.Contains(a.Detail, "Swarm service portainer_portainer") || !strings.Contains(a.Fix, "Remove `ports:`") {
		t.Errorf("portainer: %+v", a)
	}
	if s := got["exposed.swarm-manager"]; s.Severity != finding.Medium {
		t.Errorf("swarm manager: %+v", s)
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

func TestClassifyByImage(t *testing.T) {
	for image, want := range map[string]string{
		"confluentinc/cp-kafka:latest":                             "high: Kafka",
		"provectuslabs/kafka-ui:latest":                            "high: Kafka UI admin panel",
		"docker.io/library/redis:7-alpine@sha256:abc":              "high: Redis",
		"prometheuscommunity/postgres-exporter:v0.15":              "",
		"traefik:v3.6.7":                                           "",
		"10e07c83.registry.twcstorage.ru/backend:v2.0.0@sha256:9d": "",
	} {
		p := Port{Public: true, ServicePort: 29092, Image: image}
		if got := p.Risk(); got != want {
			t.Errorf("%s: got %q, want %q", image, got, want)
		}
	}
}
