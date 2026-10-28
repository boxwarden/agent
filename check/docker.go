package check

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"time"
)

var dockerSock = "/var/run/docker.sock"

// The agent is read-only (ADR-0001): only these GET endpoints may ever be called.
var dockerAllowed = map[string]bool{
	"/containers/json": true,
	"/services":        true,
}

var dockerInspectPath = regexp.MustCompile(`^/containers/[0-9a-f]{64}/json$`)

type dockerContainer struct {
	ID     string `json:"Id"`
	Names  []string
	Image  string
	Labels map[string]string
	Ports  []struct {
		IP          string
		PrivatePort int
		PublicPort  int
		Type        string
	}
}

type dockerService struct {
	Spec struct {
		Name         string
		TaskTemplate struct {
			ContainerSpec struct{ Image string }
		}
	}
	Endpoint struct {
		Ports []struct {
			Protocol      string
			TargetPort    int
			PublishedPort int
		}
	}
}

// dockerGet reads the Docker API over its unix socket. Errors (no Docker, not a Swarm manager) are normal.
func dockerGet(path string, out any) error {
	if !dockerAllowed[path] && !dockerInspectPath.MatchString(path) {
		return fmt.Errorf("docker API %s is not allowed: the agent is read-only", path)
	}
	c := http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", dockerSock)
		}},
	}
	resp, err := c.Get("http://docker" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker API %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
