// Package cloud connects the agent to the Boxwarden service. The agent only ever sends:
// it never accepts commands back (ADR-0001).
package cloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/boxwarden/agent/finding"
)

var ConfigPath = "/etc/boxwarden/agent.json"

type Config struct {
	Server string `json:"server"` // e.g. https://app.example.com
	Key    string `json:"key"`    // server key, the only credential the agent holds
}

var httpc = &http.Client{
	Timeout: 30 * time.Second,
	// A redirect could replay the key to another host or over plain http.
	CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not followed") },
}

// Enroll trades a one-time token for a permanent server key and saves it (0600).
func Enroll(server, token, hostname string) error {
	server = strings.TrimRight(server, "/")
	if u, err := url.Parse(server); err != nil || u.Scheme != "https" && !(u.Scheme == "http" && slices.Contains([]string{"localhost", "127.0.0.1", "::1"}, u.Hostname())) {
		return errors.New("server must be https:// (plain http only for localhost)")
	}
	var resp struct {
		Key string `json:"key"`
	}
	if err := post(server+"/v1/enroll", "", map[string]string{"token": token, "hostname": hostname}, &resp); err != nil {
		return err
	}
	if resp.Key == "" {
		return errors.New("server returned no key")
	}
	return save(Config{Server: server, Key: resp.Key})
}

// Push sends one report.
func Push(r finding.Report) error { return send("/v1/report", r) }

// PushMetrics sends one resource sample.
func PushMetrics(m finding.Metrics) error { return send("/v1/metrics", m) }

func send(path string, body any) error {
	b, err := os.ReadFile(ConfigPath)
	if err != nil {
		return fmt.Errorf("not enrolled (%w): run boxwarden enroll first", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("%s: %w", ConfigPath, err)
	}
	return post(c.Server+path, c.Key, body, nil)
}

func save(c Config) error {
	if err := os.MkdirAll(filepath.Dir(ConfigPath), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(ConfigPath, b, 0o600)
}

func post(url, key string, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "boxwarden-agent")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
