package check

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

// fingerprint identifies the service behind addr with harmless probes on our own host:
// read a greeting banner, else one HTTPS then one HTTP GET /. Nothing is sent that changes state.
func fingerprint(addr string) string {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return ""
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	conn.Close()
	if n > 0 {
		return banner(buf[:n])
	}
	if s := httpProbe("https://" + addr); s != "" {
		return "https " + s
	}
	if s := httpProbe("http://" + addr); s != "" {
		return "http " + s
	}
	return "unknown (no banner, not HTTP)"
}

func banner(b []byte) string {
	line, _, _ := strings.Cut(string(b), "\n")
	line = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, "SSH-"):
		return "ssh " + line
	case strings.HasPrefix(line, "220"):
		return "smtp/ftp " + line
	case len(b) > 5 && b[4] == 10: // MySQL handshake: 3-byte length, seq id, protocol version 10
		return "mysql"
	}
	for _, r := range line {
		if r < 0x20 || r > 0x7e {
			return "binary protocol"
		}
	}
	return "banner " + line[:min(60, len(line))]
}

func httpProbe(url string) string {
	c := http.Client{
		Timeout: 3 * time.Second,
		// We only identify the service on our own host, we don't trust it: self-signed certs are expected.
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := c.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	s := fmt.Sprint(resp.StatusCode)
	if m := titleRe.FindSubmatch(body); m != nil {
		s += fmt.Sprintf(" %q", strings.Join(strings.Fields(string(m[1])), " "))
	}
	if v := resp.Header.Get("Server"); v != "" {
		s += " server=" + v
	}
	if v := resp.Header.Get("Location"); v != "" {
		s += " -> " + v
	}
	return s
}
