# Security

The agent runs as root on people's servers, so we treat reports about it as urgent.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository,
or email **security@boxwarden.sh**. Please don't open a public issue. Include what you found, how to reproduce it and which version
(`boxwarden version`) you tested.

You'll get an answer within 3 days. We'll agree on a disclosure date with you, fix it in a new
release and credit you, unless you'd rather not be named.

## In scope

- The agent: anything that lets it change the system, accept input from the network, run code
  it didn't ship with, or send more than findings and the port list.
- `install.sh` and the release pipeline: anything that could get an unverified binary installed.
- The way the agent talks to the Boxwarden service (enrollment, reports, keys).

Reports about the Boxwarden service itself (app.boxwarden.sh, api.boxwarden.sh) are welcome at
the same address.

## Verifying a release

Releases are built by GitHub Actions from a tag with signed provenance:

```sh
gh attestation verify boxwarden-linux-amd64 --repo boxwarden/agent
```
