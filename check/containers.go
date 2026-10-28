package check

import (
	"slices"
	"strings"

	"github.com/boxwarden/agent/finding"
)

// containerInspect is the part of GET /containers/{id}/json that says how much of the host a container gets.
type containerInspect struct {
	HostConfig struct {
		Privileged bool
		CapAdd     []string
	}
	Mounts []struct {
		Type   string
		Source string
		RW     bool
	}
}

// Host paths a container must not write: whoever controls them controls the host.
var hostPaths = []string{"/", "/etc", "/root", "/boot", "/usr", "/bin", "/sbin", "/lib", "/var/lib/docker", "/run", "/var/run", "/proc", "/sys"}

// Docker finds containers that hand the host to whoever breaks into the app inside them.
func Docker() ([]finding.Finding, error) {
	var list []dockerContainer
	if dockerGet("/containers/json", &list) != nil {
		return nil, nil // no Docker on this host
	}
	var fs []finding.Finding
	for _, c := range list {
		var in containerInspect
		if dockerGet("/containers/"+c.ID+"/json", &in) == nil {
			fs = append(fs, containerRisks(c, in)...)
		}
	}
	return fs, nil
}

func containerRisks(c dockerContainer, in containerInspect) []finding.Finding {
	name := containerName(c)
	svc := c.Labels["com.docker.compose.service"]
	// fix says where to change it: the compose service if there is one, else the `docker run` flags.
	fix := func(compose, run string) string {
		if svc != "" {
			return "In docker-compose.yml, service " + svc + ": " + compose + ", then: docker compose up -d"
		}
		return "Recreate container " + name + " " + run
	}
	var fs []finding.Finding
	add := func(id string, sev finding.Severity, title, detail, fix string) {
		fs = append(fs, finding.Finding{ID: "docker." + id, Severity: sev, Title: title + ": " + name, Detail: detail, Fix: fix, Key: "docker." + id + "|" + name})
	}

	caps := slices.DeleteFunc(slices.Clone(in.HostConfig.CapAdd), func(c string) bool {
		c = strings.TrimPrefix(strings.ToUpper(c), "CAP_")
		return c != "ALL" && c != "SYS_ADMIN" && c != "SYS_MODULE"
	})
	switch {
	case in.HostConfig.Privileged:
		add("privileged", finding.High, "Container runs privileged",
			"A privileged container gets every device and capability of the host: a break-in into the app inside it is root on the server.",
			fix(`remove "privileged: true" (grant only what it needs with cap_add)`, "without --privileged"))
	case len(caps) > 0:
		add("capabilities", finding.High, "Container has host-level capabilities",
			"cap_add "+strings.Join(caps, ", ")+" lets a process inside mount host disks or load kernel modules: as good as privileged.",
			fix("remove "+strings.Join(caps, ", ")+" from cap_add", "without --cap-add "+strings.Join(caps, " --cap-add ")))
	}

	for _, m := range in.Mounts {
		src := m.Source
		if src != "/" {
			src = strings.TrimSuffix(src, "/")
		}
		switch {
		case m.Type != "bind":
		case src == "/var/run/docker.sock" || src == "/run/docker.sock":
			add("socket", finding.Medium, "Container can control Docker",
				"The Docker socket is mounted into it, and Docker access is root on the host: a break-in into this container is a break-in into the server. "+
					"Mounting it read-only doesn't help, the API still works. Portainer, Traefik and Watchtower need it; most apps don't.",
				fix("remove the "+src+" volume, or mount a socket proxy (tecnativa/docker-socket-proxy) that allows only the calls it needs",
					"without -v "+src))
		case m.RW && slices.Contains(hostPaths, src):
			add("host-mount", finding.High, "Container can write the host's "+src,
				"Writing "+src+" from inside a container is enough to plant a cron job, a systemd unit or an SSH key on the host.",
				fix("mount "+src+" read-only (:ro) or not at all", "with -v "+src+":…:ro or without it"))
		}
	}
	return fs
}
