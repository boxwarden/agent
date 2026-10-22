#!/bin/sh
# Boxwarden agent installer. It is short on purpose: read it before piping it to sh.
#
#   curl -fsSL <url>/install.sh | sudo sh -s ENROLL_TOKEN SERVER_URL
#
# What it does:
#   1. downloads the agent for this CPU and checks its SHA-256 against the release checksums
#      (or takes a binary you already have: BOXWARDEN_BINARY=/path/to/boxwarden)
#   2. installs it to /usr/local/bin/boxwarden
#   3. enrolls this server (the one-time token becomes a key in /etc/boxwarden, mode 0600)
#      and records the baseline to /root/boxwarden-baseline.json for you to review
#   4. installs systemd timers: ssh/ioc/exposed every 15 minutes, cve daily
# The agent only reads the system and sends findings out. It opens no ports.
set -eu

TOKEN="${1:?usage: install.sh ENROLL_TOKEN SERVER_URL}"
SERVER="${2:?usage: install.sh ENROLL_TOKEN SERVER_URL}"
REPO="${BOXWARDEN_REPO:-}"        # GitHub owner/repo with releases
VERSION="${BOXWARDEN_VERSION:-latest}"

[ "$(id -u)" = 0 ] || { echo "boxwarden: run as root (sudo)" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [ -n "${BOXWARDEN_BINARY:-}" ]; then
	cp "$BOXWARDEN_BINARY" "$tmp/boxwarden"
else
	[ -n "$REPO" ] || { echo "boxwarden: set BOXWARDEN_REPO=owner/repo or BOXWARDEN_BINARY=/path" >&2; exit 1; }
	case "$(uname -m)" in
		x86_64) arch=amd64 ;;
		aarch64 | arm64) arch=arm64 ;;
		*) echo "boxwarden: unsupported CPU $(uname -m)" >&2; exit 1 ;;
	esac
	if [ "$VERSION" = latest ]; then
		base="https://github.com/$REPO/releases/latest/download"
	else
		base="https://github.com/$REPO/releases/download/$VERSION"
	fi
	curl -fsSL "$base/boxwarden-linux-$arch" -o "$tmp/boxwarden-linux-$arch"
	curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"
	(cd "$tmp" && grep " boxwarden-linux-$arch\$" checksums.txt | sha256sum -c -)
	mv "$tmp/boxwarden-linux-$arch" "$tmp/boxwarden"
fi
install -m 0755 "$tmp/boxwarden" /usr/local/bin/boxwarden

boxwarden enroll --server "$SERVER" "$TOKEN" > /root/boxwarden-baseline.json

if ! command -v systemctl >/dev/null 2>&1; then
	echo "boxwarden: no systemd; run 'boxwarden scan --push' from cron every 15 minutes" >&2
	exit 0
fi

# Scans only read the system, so the whole filesystem is read-only for them.
# No PrivateTmp: it would hide /tmp, where attackers drop SUID shells and miners.
unit() { # name description args
	cat > "/etc/systemd/system/boxwarden-$1.service" <<EOF
[Unit]
Description=$2
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/boxwarden scan --push --checks $3
ProtectSystem=strict
ProtectHome=read-only
NoNewPrivileges=yes
EOF
}
unit scan "Boxwarden security scan" "ssh,ioc,exposed"
unit cve "Boxwarden vulnerability scan" "cve"

cat > /etc/systemd/system/boxwarden-scan.timer <<'EOF'
[Unit]
Description=Boxwarden security scan every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/boxwarden-cve.timer <<'EOF'
[Unit]
Description=Boxwarden vulnerability scan daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now boxwarden-scan.timer boxwarden-cve.timer
systemctl start boxwarden-scan.service boxwarden-cve.service || true

echo "Boxwarden is watching this server."
echo "Review the baseline NOW: /root/boxwarden-baseline.json"
echo "If the server was already compromised, the backdoor is in that list."
