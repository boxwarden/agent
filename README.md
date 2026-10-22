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
| `sshd` | Password and keyboard-interactive login, root login with a password, empty passwords |
| `exposed` | Redis, Postgres, MySQL, MongoDB, Elasticsearch, Docker API, etcd, Kafka and others listening on public interfaces; ports published by Docker that ufw does not block; Redis answering without a password |
| `cve` | OS packages on the host and in running containers with published security fixes; anything in [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (exploited in the wild) is critical |
| `ioc` | Signs of compromise: new users, SSH keys, sudo/docker group members, cron jobs, systemd units, SUID binaries and listening ports since your baseline; non-empty `/etc/ld.so.preload`; processes running from `/tmp`, `/dev/shm` or a deleted binary |

Supported: Debian and Ubuntu hosts; Debian, Ubuntu and Alpine containers.

## Install

No releases yet. Build from source (Go 1.25+):

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o heimdall ./cmd/heimdall
scp heimdall root@your-server:/usr/local/bin/
```

## Use

```sh
sudo heimdall baseline   # record what "normal" looks like
sudo heimdall scan       # run all checks
sudo heimdall scan --json
```

**Review the baseline output.** If the server is already compromised, the backdoor is now part of
"normal". Any user, key, cron job, unit or port you don't recognize is a red flag.
After you change the server on purpose, run `heimdall baseline` again.

Exit code is 1 if a check could not run (for example without root), 0 otherwise.

## What it does not do

- **Never changes your server.** Read-only. Fixes are commands for you to run.
- **Opens no ports, accepts no commands.**
- **Keeps your secrets on the server.** The baseline stores names and hashes, not file contents.

Network calls are made only by the `cve` check: it sends installed OS package names and versions
to [OSV.dev](https://osv.dev) and downloads the CISA KEV list. Nothing else leaves the machine.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require signing the [CLA](CLA.md).

## License

[AGPL-3.0](LICENSE)
