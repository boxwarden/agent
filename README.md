# Heimdall agent

Security checks for the Linux server you run yourself.
One static binary: it finds what attackers actually use against small VPS setups,
and notices when someone already got in.

```
$ sudo heimdall scan
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
| `ssh` | Password and keyboard-interactive login, root login with a password, empty passwords |
| `exposed` | Redis, Postgres, MySQL, MongoDB, Elasticsearch, Docker API, etcd, Kafka, Swarm manager and others on public interfaces, also on non-default ports; admin panels (Portainer, phpMyAdmin, Grafana, Kafka UI...); ports published by Docker or Swarm that ufw does not block; Redis answering without a password |
| `cve` | OS packages on the host and in running containers with published security fixes; anything in [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (exploited in the wild) is critical |
| `ioc` | Signs of compromise: new users, SSH keys, sudo/docker group members, cron jobs, systemd units, SUID binaries and listening ports since your baseline; non-empty `/etc/ld.so.preload`; processes running from `/tmp`, `/dev/shm` or a deleted binary |

Supported: Debian and Ubuntu hosts; Debian, Ubuntu and Alpine containers.

## Install

With a Heimdall account, the dashboard gives you a one-line install with a one-time token.
[install.sh](install.sh) is short: read it first. It checks the binary's SHA-256, enrolls the server
and adds systemd timers (ssh/ioc/exposed every 15 minutes, cve daily) that run with a read-only filesystem.

```sh
curl -fsSL <url>/install.sh | sudo sh -s ENROLL_TOKEN SERVER_URL
```

Standalone, no account: build from source (Go 1.25+):

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o heimdall ./cmd/heimdall
scp heimdall root@your-server:/usr/local/bin/
```

## Use

```sh
sudo heimdall baseline   # record what "normal" looks like
sudo heimdall scan       # run all checks
sudo heimdall scan --json
sudo heimdall ports      # every listening port: owner, service, risk
sudo heimdall scan --checks ssh,exposed   # a subset
sudo heimdall scan --push  # send the report to Heimdall cloud (after `heimdall enroll`)
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
After you change the server on purpose, run `heimdall baseline` again.

Exit code is 1 if a check could not run (for example without root), 0 otherwise.

## What it does not do

- **Never changes your server.** Read-only. Fixes are commands for you to run.
- **Opens no ports, accepts no commands.**
- **Keeps your secrets on the server.** The baseline stores names and hashes, not file contents.

With `--push`, the report (findings and the port inventory: names, no file contents) goes to the
Heimdall server you enrolled with. The agent never accepts commands back.

Apart from that, only the `cve` check talks to the outside: it sends installed OS package names and versions
to [OSV.dev](https://osv.dev) and downloads the CISA KEV list. Nothing else leaves the machine.
Port identification connects only to the server's own ports on localhost.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require signing the [CLA](CLA.md).

## License

[AGPL-3.0](LICENSE)
