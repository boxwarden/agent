#!/bin/sh
# Boxwarden agent installer. It is short on purpose: read it before piping it to sh.
#
#   curl -fsSL https://github.com/boxwarden/agent/releases/latest/download/install.sh | sh -s ENROLL_TOKEN SERVER_URL   # as root; otherwise: | sudo sh -s …
#
# On a server that is already connected, run it without arguments to update the agent:
#   curl -fsSL https://github.com/boxwarden/agent/releases/latest/download/install.sh | sudo sh
# That replaces the binary and the systemd units; the connection and the baseline stay as they are.
#
# What it does:
#   1. downloads the agent for this CPU and checks its SHA-256 against the release checksums
#      (or takes a binary you already have: BOXWARDEN_BINARY=/path/to/boxwarden)
#   2. installs it to /usr/local/bin/boxwarden
#   3. enrolls this server, unless it is already connected (the one-time token becomes a key in /etc/boxwarden, mode 0600)
#      and records the baseline to /root/boxwarden-baseline.json for you to review
#   4. installs systemd timers: all checks every 15 minutes, cve daily, resource metrics every minute
# The agent only reads the system and sends findings out. It opens no ports.
set -eu

# Everything runs from main, so a download cut short by the network never runs half a script.
main() {
	TOKEN="${1:-}"
	SERVER="${2:-}"
	CONFIG=/etc/boxwarden/agent.json
	REPO="${BOXWARDEN_REPO:-boxwarden/agent}"  # GitHub owner/repo with releases
	VERSION="${BOXWARDEN_VERSION:-latest}"
	BASELINE=/root/boxwarden-baseline.json

	# Colors and the spinner only on a terminal; NO_COLOR (https://no-color.org) turns colors off.
	TTY=
	[ -t 1 ] && TTY=1
	if [ -n "$TTY" ] && [ -z "${NO_COLOR:-}" ]; then
		B="$(printf '\033[1m')" D="$(printf '\033[2m')" E="$(printf '\033[38;5;173m')"
		G="$(printf '\033[32m')" R="$(printf '\033[31m')" Y="$(printf '\033[33m')" X="$(printf '\033[0m')"
	else
		B= D= E= G= R= Y= X=
	fi

	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	log="$tmp/log"

	ok()   { printf '  %s✓%s %s\n' "$G" "$X" "$1"; }
	warn() { printf '  %s!%s %s\n' "$Y" "$X" "$1"; }
	note() { printf '    %s%s%s\n' "$D" "$1" "$X"; }
	die()  {
		printf '  %s✗%s %s\n' "$R" "$X" "$1" >&2
		[ -s "$log" ] && tail -n 15 "$log" | sed 's/^/    /' >&2
		exit 1
	}

	# step LABEL CMD...: runs CMD with its output in $log, a spinner meanwhile; returns CMD's status.
	step() {
		label="$1"
		shift
		: >"$log"
		if [ -z "$TTY" ]; then
			"$@" >>"$log" 2>&1
			return
		fi
		"$@" >>"$log" 2>&1 &
		pid=$!
		i=0
		while kill -0 "$pid" 2>/dev/null; do
			case $((i % 8)) in
				0) f='⠋' ;; 1) f='⠙' ;; 2) f='⠹' ;; 3) f='⠸' ;; 4) f='⠼' ;; 5) f='⠴' ;; 6) f='⠦' ;; *) f='⠧' ;;
			esac
			printf '\r  %s%s%s %s' "$E" "$f" "$X" "$label"
			i=$((i + 1))
			sleep 0.1
		done
		printf '\r\033[K'
		wait "$pid"
	}

	printf '\n  %s▣%s %sboxwarden%s  agent installer\n' "$E" "$X" "$B" "$X"
	note "Reads this server and sends findings out. Changes nothing, opens no ports."
	echo

	[ "$(id -u)" = 0 ] || die "Run as root: curl -fsSL https://boxwarden.sh/install.sh | sudo sh -s TOKEN SERVER_URL"
	command -v curl >/dev/null 2>&1 || [ -n "${BOXWARDEN_BINARY:-}" ] || die "curl is required: apt install curl"
	# A second enroll would add this server to the dashboard again, without its history.
	if [ -f "$CONFIG" ]; then
		[ -z "$TOKEN" ] || die "This server is already connected. To update the agent, run the installer without a token. To connect it to another account, first: rm $CONFIG"
		update=1
	else
		[ -n "$TOKEN" ] && [ -n "$SERVER" ] || die "Not connected yet: run it with a token, as shown in your dashboard: … | sudo sh -s TOKEN SERVER_URL"
		update=
	fi

	if [ -n "${BOXWARDEN_BINARY:-}" ]; then
		cp "$BOXWARDEN_BINARY" "$tmp/boxwarden" || die "Can't read $BOXWARDEN_BINARY"
		ok "Using $BOXWARDEN_BINARY"
	else
		case "$(uname -m)" in
			x86_64) arch=amd64 ;;
			aarch64 | arm64) arch=arm64 ;;
			*) die "Unsupported CPU $(uname -m): Boxwarden runs on x86_64 and arm64" ;;
		esac
		if [ "$VERSION" = latest ]; then
			base="https://github.com/$REPO/releases/latest/download"
		else
			base="https://github.com/$REPO/releases/download/$VERSION"
		fi
		download() {
			curl -fsSL "$base/boxwarden-linux-$arch" -o "$tmp/boxwarden-linux-$arch" &&
				curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"
		}
		step "Downloading boxwarden for linux/$arch" download || die "Download failed"
		verify() { cd "$tmp" && grep " boxwarden-linux-$arch\$" checksums.txt | sha256sum -c -; }
		step "Verifying checksum" verify || die "Checksum mismatch: the download is corrupted or tampered with. Nothing was installed."
		mv "$tmp/boxwarden-linux-$arch" "$tmp/boxwarden"
		ok "Downloaded and verified (SHA-256 matches the release)"
	fi

	install -m 0755 "$tmp/boxwarden" /usr/local/bin/boxwarden
	ok "Installed boxwarden $(/usr/local/bin/boxwarden version) to /usr/local/bin"

	host="$(uname -n)"
	if [ -n "$update" ]; then
		ok "Kept the connection to $(sed -n 's/.*"server": *"[a-z]*:\/\/\([^"/]*\).*/\1/p' "$CONFIG") and the baseline"
	else
		# enroll prints a fresh baseline only when there is none yet, so a reinstall keeps the old file.
		# The token goes in on stdin, not as an argument that every user can read in the process list.
		enroll() { printf '%s' "$TOKEN" | /usr/local/bin/boxwarden enroll --server "$SERVER" - >"$tmp/baseline.json"; }
		step "Connecting $host to ${SERVER#*://}" enroll || die "Enrollment failed (tokens are single-use and expire: make a new one in the dashboard)"
		ok "Enrolled $host with ${SERVER#*://}"
		if [ -s "$tmp/baseline.json" ]; then
			install -m 0600 "$tmp/baseline.json" "$BASELINE"
			ok "Baseline recorded: users, keys, cron jobs, services, ports"
		else
			ok "Kept the existing baseline"
		fi
	fi

	if ! command -v systemctl >/dev/null 2>&1; then
		warn "No systemd here. Run scans from cron instead:"
		note "*/15 * * * *  /usr/local/bin/boxwarden scan --push --skip cve"
		note "0 4 * * *     /usr/local/bin/boxwarden scan --push --checks cve"
		note "* * * * *     /usr/local/bin/boxwarden metrics --push"
		exit 0
	fi

	# Scans only read the system, so the whole filesystem is read-only for them.
	# No PrivateTmp: it would hide /tmp, where attackers drop SUID shells and miners.
	unit() { # name description command
		cat >"/etc/systemd/system/boxwarden-$1.service" <<EOF
[Unit]
Description=$2
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/boxwarden $3
ProtectSystem=strict
ProtectHome=read-only
NoNewPrivileges=yes
TimeoutStartSec=15min
MemoryMax=512M
Environment=GOMEMLIMIT=384MiB
Nice=10
EOF
	}
	# Every check except cve, so checks added in new agent versions run without reinstalling.
	unit scan "Boxwarden security scan" "scan --push --skip cve"
	unit cve "Boxwarden vulnerability scan" "scan --push --checks cve"
	unit metrics "Boxwarden resource metrics" "metrics --push"

	cat >/etc/systemd/system/boxwarden-scan.timer <<'EOF'
[Unit]
Description=Boxwarden security scan every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
EOF

	cat >/etc/systemd/system/boxwarden-cve.timer <<'EOF'
[Unit]
Description=Boxwarden vulnerability scan daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

	cat >/etc/systemd/system/boxwarden-metrics.timer <<'EOF'
[Unit]
Description=Boxwarden resource metrics every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

	systemctl daemon-reload
	systemctl enable --now boxwarden-scan.timer boxwarden-cve.timer boxwarden-metrics.timer >"$log" 2>&1 || die "Couldn't enable the timers"
	ok "Timers on: security scan every 15 minutes, CVE scan daily, resources every minute"

	if step "Running the first scan" systemctl start boxwarden-scan.service; then
		ok "First scan sent"
	else
		warn "First scan failed; see: journalctl -u boxwarden-scan"
	fi
	systemctl start --no-block boxwarden-cve.service
	ok "CVE scan started in the background"

	if [ -n "$update" ]; then
		printf '\n  %sUpdated.%s Boxwarden keeps watching %s%s%s.\n' "$B" "$X" "$B" "$host" "$X"
	else
		printf '\n  %sDone.%s Boxwarden is watching %s%s%s.\n' "$B" "$X" "$B" "$host" "$X"
		note "It shows up in your dashboard within a minute."
	fi
	echo
	if [ -s "$tmp/baseline.json" ]; then
		warn "Review the baseline now: less $BASELINE"
		note "If this server was already compromised, the backdoor is in that list."
		echo
	fi
}

main "$@"
