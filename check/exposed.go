package check

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/boxwarden/agent/finding"
)

// noAuth probes ask a service a harmless read-only question and report whether it answered without
// credentials. Swapped in tests so they don't depend on local databases.
var noAuth = map[string]func(addr string) bool{
	"redis":         redisNoAuth,
	"postgres":      postgresTrust,
	"memcached":     memcachedOpen,
	"elasticsearch": func(addr string) bool { return httpOpen(addr, "/") },
	"couchdb":       func(addr string) bool { return httpOpen(addr, "/_all_dbs") },
}

var noAuthWhy = map[string]string{
	"redis":         "Redis can also be made to write files: a common way to plant SSH keys and miners.",
	"postgres":      "pg_hba.conf trusts remote connections, and superusers can run shell commands (COPY ... PROGRAM).",
	"elasticsearch": "Bots wipe open clusters and leave a ransom note.",
	"couchdb":       "Bots wipe open databases and leave a ransom note.",
}

// Exposed reports risky services and admin panels listening on public addresses.
// It can't see the firewall, so wording stays "reachable unless blocked"; the external scan confirms.
func Exposed() ([]finding.Finding, error) {
	return ExposedIn(Inventory(true)), nil
}

// ExposedIn is Exposed for an inventory the caller already has, so ports are probed once per scan.
func ExposedIn(ports []Port) []finding.Finding {
	return exposed(ports, ufwEnabled("/"))
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
			Fix:    "Bind it to 127.0.0.1 in its config, or block port " + hp + " in your provider's cloud firewall",
		}
		if ufw {
			f.Fix = "Bind it to 127.0.0.1 in its config, or block it: sudo ufw deny " + hp
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
		if probe := noAuth[id]; probe != nil && probe(dialAddr(p.Addr)) {
			f.Severity = finding.Critical
			f.Title = name + " is exposed on port " + hp + " with no password"
			f.Detail += " It answered without credentials: anyone on the internet can read and change the data. " + noAuthWhy[id]
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
	line, _ := bufio.NewReader(io.LimitReader(conn, 64)).ReadString('\n') // a fake Redis could stream forever
	return strings.HasPrefix(line, "+PONG")
}

// postgresTrust sends a startup packet as "postgres" with no password: AuthenticationOk means trust auth.
func postgresTrust(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	params := "user\x00postgres\x00database\x00postgres\x00\x00"
	msg := binary.BigEndian.AppendUint32(nil, uint32(8+len(params)))
	msg = binary.BigEndian.AppendUint32(msg, 196608) // protocol 3.0
	if _, err := conn.Write(append(msg, params...)); err != nil {
		return false
	}
	var resp [9]byte // 'R', length, auth code
	if _, err := io.ReadFull(conn, resp[:]); err != nil || resp[0] != 'R' {
		return false
	}
	conn.Write([]byte{'X', 0, 0, 0, 4}) // Terminate
	return binary.BigEndian.Uint32(resp[5:]) == 0
}

func memcachedOpen(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return false
	}
	line, _ := bufio.NewReader(io.LimitReader(conn, 64)).ReadString('\n')
	return strings.HasPrefix(line, "VERSION ")
}

// httpOpen: a GET answered 200 without credentials, over http or https.
func httpOpen(addr, path string) bool {
	c := http.Client{
		Timeout:       3 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // our own host
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, scheme := range []string{"http://", "https://"} {
		if resp, err := c.Get(scheme + addr + path); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
	}
	return false
}
