// Package cloud connects the agent to the Heimdall service. The agent only ever sends:
// it never accepts commands back (ADR-0001).
package cloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/d3f4u1t/heimdall-agent/finding"
)

var ConfigPath = "/etc/heimdall/agent.json"

type Config struct {
	Server string `json:"server"` // e.g. https://app.example.com
	Key    string `json:"key"`    // server key, the only credential the agent holds
}

var httpc = &http.Client{Timeout: 30 * time.Second}

// Enroll trades a one-time token for a permanent server key and saves it (0600).
func Enroll(server, token, hostname string) error {
	server = strings.TrimRight(server, "/")
	if !strings.HasPrefix(server, "https://") && !strings.HasPrefix(server, "http://localhost") && !strings.HasPrefix(server, "http://127.0.0.1") {
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
func Push(r finding.Report) error {
	b, err := os.ReadFile(ConfigPath)
	if err != nil {
		return fmt.Errorf("not enrolled (%w): run heimdall enroll first", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("%s: %w", ConfigPath, err)
	}
	return post(c.Server+"/v1/report", c.Key, r, nil)
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
	req.Header.Set("User-Agent", "heimdall-agent")
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
