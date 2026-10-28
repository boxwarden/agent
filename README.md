# Boxwarden agent

Security checks for the Linux server you run yourself.
One static binary: it finds what attackers actually use against small VPS setups,
and notices when someone already got in.

```
$ sudo boxwarden scan
[critical] Redis is exposed on port 6379 with no password
  Published by Docker on 0.0.0.0:6379, [::]:6379. Docker writes its own iptables rules, so ufw does NOT block this port.
  fix: In docker-compose.yml publish as "127.0.0.1:6379:6379" instead of "6379:6379", then: docker compose up -d

[critical] Login-capable user added since baseline: sysupd
  uid=0 shell=/bin/sh
  fix: If you didn't make this change, assume compromise: ...
```

## What it checks

| Check | Finds |
|---|---|
| `ssh` | Password and keyboard-interactive login, root login with a password (unless root's password is locked), empty passwords |
| `auth` | A second UID 0 account, accounts with no password, SSH keys planted in service accounts (`www-data`, `redis`, `postgres`...) |
| `files` | `/etc/passwd`, sudoers, cron, systemd units, `PATH` directories and other root-only files writable by users or owned by non-root; readable `/etc/shadow` |
| `updates` | End-of-life OS releases (Ubuntu Pro counts as supported), security updates waiting for a reboot, no automatic updates and nothing patched in two weeks |
| `exposed` | Redis, Postgres, MySQL, MongoDB, Elasticsearch, Docker API, etcd, Kafka, Ollama, ClickHouse, VNC, SMB and others on public addresses, also on non-default ports; admin panels (Portainer, phpMyAdmin, Grafana, Jupyter...); ports published by Docker or Swarm that ufw does not block; Redis, Postgres, Elasticsearch, CouchDB and Memcached answering without a password. Binds to private, Tailscale and docker addresses are not "exposed" |
| `cve` | OS packages on the host and in running containers with published security fixes; anything in [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (exploited in the wild) is critical |
| `ioc` | Signs of compromise: new users, SSH keys, sudo/docker group members, cron jobs, systemd units, SUID binaries and listening ports since your baseline; non-empty `/etc/ld.so.preload`; crypto miners, also renamed ones connected to a mining pool; processes posing as kernel threads; reverse shells; processes running from `/tmp`, `/dev/shm`, memory or a deleted binary; root SUID binaries in temp and home directories |
| `integrity` | `sshd`, `sudo`, `su`, `ps`, `ls`, `ss`, `netstat`, PAM modules and other binaries rootkits replace, checked against the MD5s dpkg recorded at install |
| `docker` | Containers that hand the host to whoever breaks into them: privileged, `SYS_ADMIN`-level capabilities, the Docker socket mounted, `/`, `/etc` or `/root` of the host mounted writable |
| `tls` | Let's Encrypt certificates (certbot, Caddy) that expired or that renewal has stopped replacing |

All checks except `cve` and `integrity` work on any Linux (RHEL, AlmaLinux and Rocky included). `cve` covers Debian and Ubuntu hosts and Debian, Ubuntu and Alpine containers; `integrity` covers Debian and Ubuntu.

## Install

With a Boxwarden account, the dashboard gives you a one-line install with a one-time token.
[install.sh](install.sh) is short: read it first. It checks the binary's SHA-256, enrolls the server
and adds systemd timers (every check every 15 minutes, cve daily, resource metrics every minute) that run with a read-only filesystem.

```sh
curl -fsSL https://github.com/boxwarden/agent/releases/latest/download/install.sh | sudo sh -s ENROLL_TOKEN https://api.boxwarden.sh
```

To update the agent on a server that is already connected, run the installer without a token.
It replaces the binary and the systemd units and keeps the connection and the baseline:

```sh
curl -fsSL https://github.com/boxwarden/agent/releases/latest/download/install.sh | sudo sh
```

Releases are built by [GitHub Actions](.github/workflows/release.yml) from the tag, with no build cache,
and carry signed build provenance. To check that a binary came from this repo's workflow:

```sh
gh attestation verify boxwarden-linux-amd64 --repo boxwarden/agent
```

Standalone, no account: download `boxwarden-linux-amd64` from [Releases](https://github.com/boxwarden/agent/releases)
or build from source (Go 1.25+):

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o boxwarden ./cmd/boxwarden
scp boxwarden root@your-server:/usr/local/bin/
```

## Use

```sh
sudo boxwarden baseline   # record what "normal" looks like
sudo boxwarden scan       # run all checks
sudo boxwarden scan --json
sudo boxwarden ports      # every listening port: owner, service, risk
sudo boxwarden metrics    # CPU, memory, disks, network, busiest processes
sudo boxwarden scan --checks ssh,exposed   # a subset
sudo boxwarden scan --skip cve            # everything but the slow one
sudo boxwarden scan --push  # send the report to Boxwarden cloud (after `boxwarden enroll`)
```

```
ADDRESS        OWNER                                               SERVICE                        RISK
0.0.0.0:22     sshd (ssh.service)                                  ssh SSH-2.0-OpenSSH_9.2p1
0.0.0.0:9443   swarm portainer_portainer [portainer/portainer-ce]  https 200 "Portainer"          high: Portainer admin panel
0.0.0.0:55432  docker app-db-1 [postgres:16]                       unknown (no banner, not HTTP)  high: PostgreSQL
```

To identify a port the agent finds the owning process, asks the Docker API which container or Swarm
service publishes it (`GET` only, on an allowlist), and for public ports reads the greeting banner or
makes one `GET /` to the port on localhost. It never sends anything that changes state.

**Review the baseline output.** If the server is already compromised, the backdoor is now part of
"normal". Any user, key, cron job, unit or port you don't recognize is a red flag.
After you change the server on purpose, run `boxwarden baseline` again.

Exit code is 1 if a check could not run (for example without root), 0 otherwise.

## What it does not do

- **Never changes your server.** Read-only. Fixes are commands for you to run.
- **Opens no ports, accepts no commands.**
- **Keeps your secrets on the server.** The baseline stores names and hashes, not file contents.

With `--push`, the report (findings and the port inventory: names, no file contents) goes to the
Boxwarden server you enrolled with. The agent never accepts commands back.

Apart from that, only the `cve` check talks to the outside: it sends installed OS package names and versions
to [OSV.dev](https://osv.dev) and downloads the CISA KEV list. Nothing else leaves the machine.
Port identification connects only to the server's own ports on localhost.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require signing the [CLA](CLA.md).

## License

[AGPL-3.0](LICENSE)
