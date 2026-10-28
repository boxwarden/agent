package check

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestTLSCerts(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	cert := func(name string, from time.Time, days int) string {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
			NotBefore: from, NotAfter: from.AddDate(0, 0, days)}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	root := t.TempDir()
	write(t, root, "etc/letsencrypt/live/ok.example/cert.pem", cert("ok.example", now.AddDate(0, 0, -20), 90))       // 70 days left
	write(t, root, "etc/letsencrypt/live/stuck.example/cert.pem", cert("stuck.example", now.AddDate(0, 0, -80), 90)) // 10 left
	write(t, root, "etc/letsencrypt/live/gone.example/cert.pem", cert("gone.example", now.AddDate(0, 0, -100), 90))  // expired
	write(t, root, "var/lib/caddy/.local/share/caddy/certificates/acme/short.example/short.example.crt",
		cert("short.example", now.AddDate(0, 0, -4), 6)) // 2 of 6 days left: renewal is due, not failing

	var got []string
	for _, f := range tlsCerts(root, now) {
		got = append(got, f.Key+" | "+f.Title)
	}
	want := []string{
		"tls.expired|/etc/letsencrypt/live/gone.example/cert.pem | TLS certificate expired: gone.example",
		"tls.expiring|/etc/letsencrypt/live/stuck.example/cert.pem | TLS certificate expires in 10 day(s) and isn't being renewed: stuck.example",
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got\n%q", got)
	}
}
