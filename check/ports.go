package check

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/boxwarden/agent/finding"
)

// Port is one listening TCP socket with everything we could learn about it.
type Port struct {
	Addr   string `json:"addr"`
	Port   int    `json:"port"`
	Public bool   `json:"public"` // bound to all interfaces or a global address

	PID     string `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
	Unit    string `json:"unit,omitempty"` // systemd unit

	Container   string `json:"container,omitempty"` // container or Swarm service name
	Image       string `json:"image,omitempty"`
	Published   string `json:"published,omitempty"` // "docker" or "swarm": these bypass ufw
	ServicePort int    `json:"service_port"`        // port inside the container, identifies the service

	Service string `json:"service,omitempty"` // fingerprint, public ports only
}

var cgnat = &net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)}

// publicIP: could the internet reach this listen address? 0.0.0.0 and :: listen on every interface.
// Private, Tailscale (100.64/10), docker0 and link-local binds are reachable only from inside.
func publicIP(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !cgnat.Contains(ip)
}

var unitRe = regexp.MustCompile(`/([^/]+\.service)`)

// Inventory lists listening ports with owner and, if probe is set, a fingerprint of public ones.
func Inventory(probe bool) []Port {
	return inventory("/", probe)
}

func inventory(root string, probe bool) []Port {
	type pub struct {
		kind, name, image string
		target            int
	}
	published := map[int]pub{}
	byID := map[string]dockerContainer{}
	var containers []dockerContainer
	dockerGet("/containers/json", &containers) // no Docker: nothing published by it
	for _, c := range containers {
		byID[c.ID] = c
		for _, p := range c.Ports {
			if p.PublicPort > 0 && p.Type == "tcp" {
				published[p.PublicPort] = pub{"docker", containerName(c), c.Image, p.PrivatePort}
			}
		}
	}
	// Swarm ingress ports are held by dockerd itself, so only the API knows which service owns them.
	var services []dockerService
	dockerGet("/services", &services) // fails unless this node is a Swarm manager
	for _, s := range services {
		for _, p := range s.Endpoint.Ports {
			if p.PublishedPort > 0 && p.Protocol == "tcp" {
				published[p.PublishedPort] = pub{"swarm", s.Spec.Name, s.Spec.TaskTemplate.ContainerSpec.Image, p.TargetPort}
			}
		}
	}

	owners := socketOwners(root)
	var ports []Port
	for _, sock := range listening(root) {
		host, ps, _ := net.SplitHostPort(sock.addr)
		n, _ := strconv.Atoi(ps)
		p := Port{Addr: sock.addr, Port: n, Public: publicIP(net.ParseIP(host)), ServicePort: n}
		if pid := owners[sock.inode]; pid != "" {
			p.PID = pid
			p.Process = finding.Clean(strings.TrimSpace(readFile(root, "proc/"+pid+"/comm")), 64) // set by the process itself
			cg := readFile(root, "proc/"+pid+"/cgroup")
			if id := containerRe.FindString(cg); id != "" {
				if c, ok := byID[id]; ok {
					p.Container, p.Image = containerName(c), c.Image
				} else {
					p.Container = id[:12]
				}
			} else if m := unitRe.FindAllStringSubmatch(cg, -1); m != nil {
				p.Unit = m[len(m)-1][1]
			}
		}
		if pb, ok := published[n]; ok {
			p.Published, p.Container, p.Image, p.ServicePort = pb.kind, pb.name, pb.image, pb.target
		}
		ports = append(ports, p)
	}

	if probe {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 16) // a user can open thousands of listeners
		for i := range ports {
			if ports[i].Public {
				wg.Go(func() {
					sem <- struct{}{}
					defer func() { <-sem }()
					// Whoever listens on the port writes this text: never trust it.
					ports[i].Service = finding.Clean(fingerprint(dialAddr(ports[i].Addr)), 200)
				})
			}
		}
		wg.Wait()
	}
	return ports
}

// socketOwners maps socket inode -> pid by reading /proc/<pid>/fd links ("socket:[12345]").
func socketOwners(root string) map[string]string {
	owners := map[string]string{}
	entries, _ := os.ReadDir(filepath.Join(root, "proc"))
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		fdDir := filepath.Join(root, "proc", e.Name(), "fd")
		fds, _ := os.ReadDir(fdDir)
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if inode, ok := strings.CutPrefix(link, "socket:["); err == nil && ok {
				inode = strings.TrimSuffix(inode, "]")
				if owners[inode] == "" {
					owners[inode] = e.Name()
				}
			}
		}
	}
	return owners
}

func containerName(c dockerContainer) string {
	if s := c.Labels["com.docker.swarm.service.name"]; s != "" {
		return s
	}
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	return c.ID[:min(12, len(c.ID))]
}

// Owner is a one-line "who holds this port" for humans.
func (p Port) Owner() string {
	var s string
	switch {
	case p.Published != "":
		s = p.Published + " " + p.Container
	case p.Container != "":
		s = "container " + p.Container
	default:
		s = p.Process
		if p.Unit != "" {
			s += " (" + p.Unit + ")"
		}
	}
	if p.Image != "" {
		s += " [" + p.Image + "]"
	}
	if s == "" {
		s = "?"
	}
	return s
}

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
	9092:  {"kafka", "Kafka", finding.High},
	2181:  {"zookeeper", "ZooKeeper", finding.High},
	5672:  {"rabbitmq", "RabbitMQ", finding.Medium},
	8086:  {"influxdb", "InfluxDB", finding.Medium},
	11434: {"ollama", "Ollama API (no auth: anyone can run and pull models)", finding.High},
	9042:  {"cassandra", "Cassandra", finding.High},
	8123:  {"clickhouse", "ClickHouse HTTP", finding.High},
	1433:  {"mssql", "Microsoft SQL Server", finding.High},
	7474:  {"neo4j", "Neo4j", finding.Medium},
	5900:  {"vnc", "VNC remote desktop", finding.High},
	445:   {"smb", "SMB file sharing", finding.High},
	111:   {"rpcbind", "rpcbind (NFS portmapper)", finding.Medium},
	2377:  {"swarm-manager", "Docker Swarm manager API", finding.Medium},
	7946:  {"swarm-gossip", "Docker Swarm node gossip", finding.Medium},
}

// Admin UIs give control of the server or its data. Matched on the HTTP title, or on images that
// only ever serve a panel. Never on generic proxies: Traefik's image on :443 serves your apps.
var adminTitles = map[string]string{
	"portainer": "Portainer", "phpmyadmin": "phpMyAdmin", "adminer": "Adminer", "pgadmin": "pgAdmin",
	"grafana": "Grafana", "kibana": "Kibana", "jenkins": "Jenkins", "traefik": "Traefik dashboard",
	"rabbitmq management": "RabbitMQ management", "prometheus": "Prometheus", "n8n": "n8n", "coolify": "Coolify",
	"dozzle": "Dozzle", "netdata": "Netdata", "webmin": "Webmin", "cockpit": "Cockpit", "mongo express": "Mongo Express",
	"ui for apache kafka": "Kafka UI", "redisinsight": "RedisInsight", "jupyter": "Jupyter (runs code)",
	"ray dashboard": "Ray dashboard (runs code)", "mailhog": "MailHog", "mailpit": "Mailpit",
}
var adminImages = map[string]string{
	"portainer": "Portainer", "portainer-ce": "Portainer", "portainer-ee": "Portainer", "phpmyadmin": "phpMyAdmin", "adminer": "Adminer", "pgadmin4": "pgAdmin",
	"grafana": "Grafana", "dozzle": "Dozzle", "mongo-express": "Mongo Express", "kafka-ui": "Kafka UI", "redisinsight": "RedisInsight",
}

// riskyImages catches risky services on non-default ports (Kafka on 29092) by image name -> its riskyPorts entry.
var riskyImages = map[string]int{
	"redis": 6379, "postgres": 5432, "mysql": 3306, "mariadb": 3306, "mongo": 27017, "elasticsearch": 9200,
	"kafka": 9092, "zookeeper": 2181, "memcached": 11211, "couchdb": 5984, "rabbitmq": 5672, "influxdb": 8086,
	"etcd": 2379, "consul": 8500, "ollama": 11434, "cassandra": 9042, "neo4j": 7474,
}

// classify returns why a public port is dangerous, if it is.
func classify(p Port) (id, name string, sev finding.Severity, ok bool) {
	if !p.Public {
		return "", "", "", false
	}
	if r, risky := riskyPorts[p.ServicePort]; risky {
		return r.id, r.name, r.sev, true
	}
	title := strings.ToLower(p.Service)
	for k, n := range adminTitles {
		if strings.Contains(title, k) {
			return "admin-panel", n + " admin panel", finding.High, true
		}
	}
	img := imageName(p.Image)
	if n, ok := adminImages[img]; ok {
		return "admin-panel", n + " admin panel", finding.High, true
	}
	// "cp-kafka" -> kafka, but not "kafka-ui" or "postgres-exporter": only the last dash segment counts.
	if port, ok := riskyImages[img[strings.LastIndex(img, "-")+1:]]; ok {
		r := riskyPorts[port]
		return r.id, r.name, r.sev, true
	}
	return "", "", "", false
}

// imageName is the bare repository name: "docker.io/confluentinc/cp-kafka:7.6@sha256:.." -> "cp-kafka".
func imageName(image string) string {
	image, _, _ = strings.Cut(strings.ToLower(image), "@")
	image = image[strings.LastIndex(image, "/")+1:]
	image, _, _ = strings.Cut(image, ":")
	return image
}

// Risk is a short label for the ports table; "" when the port is not a known risk.
func (p Port) Risk() string {
	if _, name, sev, ok := classify(p); ok {
		return string(sev) + ": " + name
	}
	return ""
}
