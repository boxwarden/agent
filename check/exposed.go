package check

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d3f4u1t/heimdall-agent/finding"
)

// Services that must never face the internet. Most ship without auth or get brute-forced.
var riskyPorts = map[int]struct {
	id, name string
	sev      finding.Severity
}{
	2375:  {"docker-api", "Docker API (plain TCP, no auth = root)", finding.Critical},
	2376:  {"docker-api-tls", "Docker API (TLS)", finding.High},
	2379:  {"etcd", "etcd", finding.Critical},
	10250: {"kubelet", "Kubelet API", finding.Critical},
	6379:  {"redis", "Redis", finding.High},
	5432:  {"postgres", "PostgreSQL", finding.High},
	3306:  {"mysql", "MySQL/MariaDB", finding.High},
	27017: {"mongodb", "MongoDB", finding.High},
	9200:  {"elasticsearch", "Elasticsearch", finding.High},
	11211: {"memcached", "Memcached", finding.High},
	5984:  {"couchdb", "CouchDB", finding.High},
	8500:  {"consul", "Consul", finding.High},
	5672:  {"rabbitmq", "RabbitMQ", finding.Medium},
	15672: {"rabbitmq-ui", "RabbitMQ management UI", finding.Medium},
	8086:  {"influxdb", "InfluxDB", finding.Medium},
	9092:  {"kafka", "Kafka", finding.High},
	2181:  {"zookeeper", "ZooKeeper", finding.High},
}

// probeRedis is swapped in tests so they don't depend on a local Redis.
var probeRedis = redisNoAuth

// Exposed reports risky services listening on non-loopback addresses.
// It can't see the firewall, so wording stays "reachable unless blocked"; the external scan confirms.
func Exposed() ([]finding.Finding, error) {
	return exposed("/"), nil
}

func exposed(root string) []finding.Finding {
	// Docker maps arbitrary host ports (5433, 55432...) to the real service port, so identify by container port.
	docker := dockerPublished(root)
	svcPort := func(hostPort int) int {
		if cp, ok := docker[hostPort]; ok {
			return cp
		}
		return hostPort
	}

	byPort := map[int][]string{}
	for _, addr := range listening(root) {
		host, p, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(p)
		if _, risky := riskyPorts[svcPort(port)]; !risky || net.ParseIP(host).IsLoopback() {
			continue
		}
		byPort[port] = append(byPort[port], addr)
	}

	ufw := ufwEnabled(root)

	var fs []finding.Finding
	for port, addrs := range byPort {
		svc := riskyPorts[svcPort(port)]
		hp := strconv.Itoa(port)
		f := finding.Finding{
			ID: "exposed." + svc.id, Severity: svc.sev,
			Title:  svc.name + " is exposed on port " + hp,
			Detail: "Listening on " + strings.Join(addrs, ", ") + ". Reachable from the internet unless a firewall blocks it.",
			Fix:    "Bind it to 127.0.0.1 in its config, or block it: sudo ufw deny " + hp,
		}
		if cp, ok := docker[port]; ok {
			mapping := hp + ":" + strconv.Itoa(cp)
			f.Detail = "Published by Docker on " + strings.Join(addrs, ", ") + ". Docker writes its own iptables rules, so ufw does NOT block this port."
			if ufw {
				f.Detail += " ufw is enabled, which makes this look protected when it isn't."
			}
			f.Fix = `In docker-compose.yml publish as "127.0.0.1:` + mapping + `" instead of "` + mapping + `", then: docker compose up -d`
		}
		if svc.id == "redis" && probeRedis(dialAddr(addrs[0])) {
			f.Severity = finding.Critical
			f.Title = "Redis is exposed on port " + hp + " with no password"
			f.Detail += " It answered PING without auth: anyone can read your data and write files (a common way to plant SSH keys and miners)."
		}
		fs = append(fs, f)
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].Title < fs[j].Title })
	return fs
}

// dockerPublished maps host port -> container port from Docker's userland proxy processes.
// Matched by flags, not binary name: the proxy path is configurable (OrbStack uses "pstub").
// ponytail: with "userland-proxy": false there is no proxy and nothing in /proc/net/tcp; read iptables DNAT if that setup shows up.
func dockerPublished(root string) map[int]int {
	ports := map[int]int{}
	entries, _ := os.ReadDir(filepath.Join(root, "proc"))
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(root, "proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		flags := map[string]string{}
		for i := 1; i+1 < len(args); i++ {
			if strings.HasPrefix(args[i], "-") {
				flags[args[i]] = args[i+1]
			}
		}
		hp, err1 := strconv.Atoi(flags["-host-port"])
		cp, err2 := strconv.Atoi(flags["-container-port"])
		if err1 == nil && err2 == nil && flags["-container-ip"] != "" {
			ports[hp] = cp
		}
	}
	return ports
}

func ufwEnabled(root string) bool {
	b, _ := os.ReadFile(filepath.Join(root, "etc/ufw/ufw.conf"))
	for line := range strings.SplitSeq(string(b), "\n") {
		if strings.TrimSpace(line) == "ENABLED=yes" {
			return true
		}
	}
	return false
}

// dialAddr turns a wildcard listen address into one we can connect to locally.
func dialAddr(addr string) string {
	host, port, _ := net.SplitHostPort(addr)
	switch host {
	case "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}

// redisNoAuth sends PING (read-only) and reports whether Redis answered without a password.
func redisNoAuth(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return false
	}
	line, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.HasPrefix(line, "+PONG")
}
