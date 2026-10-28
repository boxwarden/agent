package check

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/boxwarden/agent/finding"
)

// Where certbot and Caddy keep the certificates they renew. ponytail: Traefik's acme.json lives in a
// volume we can't guess; add it if users ask.
var certGlobs = []string{
	"etc/letsencrypt/live/*/cert.pem",
	"var/lib/caddy/.local/share/caddy/certificates/*/*/*.crt",
	"root/.local/share/caddy/certificates/*/*/*.crt",
}

// TLS finds certificates that expired or whose automatic renewal is failing.
func TLS() ([]finding.Finding, error) { return tlsCerts("/", time.Now()), nil }

func tlsCerts(root string, now time.Time) []finding.Finding {
	var fs []finding.Finding
	for _, g := range certGlobs {
		paths, _ := filepath.Glob(filepath.Join(root, g))
		for _, p := range paths {
			block, _ := pem.Decode([]byte(readFile(root, rel(root, p))))
			if block == nil {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			name := c.Subject.CommonName
			if len(c.DNSNames) > 0 {
				name = c.DNSNames[0]
			}
			fix := "journalctl -u caddy | grep -iE 'obtain|renew'   # Caddy can't reach the CA, or the domain no longer points here"
			if lineage, ok := strings.CutPrefix(rel(root, p), "/etc/letsencrypt/live/"); ok {
				lineage = filepath.Dir(lineage)
				fix = "sudo certbot renew --cert-name " + shQuote(lineage) + " --dry-run   # shows why renewal fails; if the domain is gone: sudo certbot delete --cert-name " + shQuote(lineage)
			}
			left := c.NotAfter.Sub(now)
			// Renewal starts with a third of the lifetime left (30 of 90 days, 2 of 6): a sixth left
			// means it has been failing for a while, whatever the lifetime.
			switch {
			case left <= 0:
				fs = append(fs, finding.Finding{
					ID: "tls.expired", Severity: finding.High,
					Title:  "TLS certificate expired: " + name,
					Detail: "Expired " + c.NotAfter.Format("2006-01-02") + ". Browsers refuse the site and API clients fail. File: " + rel(root, p),
					Fix:    fix, Key: "tls.expired|" + rel(root, p),
				})
			case left < c.NotAfter.Sub(c.NotBefore)/6:
				fs = append(fs, finding.Finding{
					ID: "tls.expiring", Severity: finding.Medium,
					Title:  "TLS certificate expires in " + strconv.Itoa(int(left.Hours()/24)) + " day(s) and isn't being renewed: " + name,
					Detail: "Expires " + c.NotAfter.Format("2006-01-02") + "; renewal should have replaced it by now. File: " + rel(root, p),
					Fix:    fix, Key: "tls.expiring|" + rel(root, p),
				})
			}
		}
	}
	return fs
}
