package check

import (
	"bufio"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d3f4u1t/heimdall-agent/finding"
)

// probeRedis is swapped in tests so they don't depend on a local Redis.
var probeRedis = redisNoAuth

// Exposed reports risky services and admin panels listening on public addresses.
// It can't see the firewall, so wording stays "reachable unless blocked"; the external scan confirms.
func Exposed() ([]finding.Finding, error) {
	return exposed(Inventory(true), ufwEnabled("/")), nil
}

func exposed(ports []Port, ufw bool) []finding.Finding {
	// 0.0.0.0:6379 and [::]:6379 are one service: group by port.
	byPort := map[int][]Port{}
	for _, p := range ports {
		if _, _, _, risky := classify(p); risky {
			byPort[p.Port] = append(byPort[p.Port], p)
		}
	}

	var fs []finding.Finding
	for port, ps := range byPort {
		p := ps[0]
		id, name, sev, _ := classify(p)
		var addrs []string
		for _, q := range ps {
			addrs = append(addrs, q.Addr)
		}
		hp := strconv.Itoa(port)
		f := finding.Finding{
			ID: "exposed." + id, Severity: sev,
			Title:  name + " is exposed on port " + hp,
			Detail: "Listening on " + strings.Join(addrs, ", ") + " (" + p.Owner() + "). Reachable from the internet unless a firewall blocks it.",
			Fix:    "Bind it to 127.0.0.1 in its config, or block it: sudo ufw deny " + hp,
		}
		if id == "admin-panel" {
			f.Fix = "Put it behind your reverse proxy with authentication, or don't publish it and use an SSH tunnel: ssh -L " + hp + ":localhost:" + hp + " root@your-server"
		}
		switch p.Published {
		case "docker":
			mapping := hp + ":" + strconv.Itoa(p.ServicePort)
			f.Detail = "Published by Docker (" + strings.TrimPrefix(p.Owner(), "docker ") + ") on " + strings.Join(addrs, ", ") + ". Docker writes its own iptables rules, so ufw does NOT block this port."
			f.Fix = `In docker-compose.yml publish as "127.0.0.1:` + mapping + `" instead of "` + mapping + `", then: docker compose up -d`
		case "swarm":
			f.Detail = "Published by Swarm service " + p.Container + " on " + strings.Join(addrs, ", ") + ". Swarm's ingress writes its own iptables rules, so ufw does NOT block this port."
			f.Fix = "Remove `ports:` from service " + p.Container + " and reach it over the overlay network or through your reverse proxy; or filter it in the DOCKER-USER iptables chain."
		}
		if p.Published != "" && ufw {
			f.Detail += " ufw is enabled, which makes this look protected when it isn't."
		}
		if id == "redis" && probeRedis(dialAddr(p.Addr)) {
			f.Severity = finding.Critical
			f.Title = "Redis is exposed on port " + hp + " with no password"
			f.Detail += " It answered PING without auth: anyone can read your data and write files (a common way to plant SSH keys and miners)."
		}
		fs = append(fs, f)
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].Title < fs[j].Title })
	return fs
}

func ufwEnabled(root string) bool {
	for line := range strings.SplitSeq(readFile(root, "etc/ufw/ufw.conf"), "\n") {
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
