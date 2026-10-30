# Cassandra V18: English summary

*The documentation is written in French (the project's working language). This page is a short summary for English-speaking readers; the full README is [`README.md`](README.md) and the product guide is [`V18/README.md`](V18/README.md).*

**Cassandra is a sovereign, self-hosted AI agent for system administration.** It runs on your own server, sees what happens there, understands it, acts when it is safe (inside a cage, with an automatic rollback where possible) and tells you about it. You talk to it like to a person; it answers by looking at the machine, not by guessing. It depends on no single vendor: an API key, an OpenAI-compatible server, or a local Ollama.

License: [AGPL-3.0-or-later](LICENSE).

## State of the project

| Version | State | Where |
|---|---|---|
| **V18** | the production version, a product to install on Debian or Ubuntu | [`V18/`](V18/) |
| **V19** | modular rewrite (a tiny kernel plus modules that declare themselves by a manifest), developed alongside | repository [`cassandra-v19`](https://github.com/Marplestrange/cassandra-v19) |
| V3.2 – V14 | the history of the project, from a minimal agent to a full dashboard | folders `V3.2` … `V14`, see [`LISEZ-MOI-HISTORIQUE.md`](LISEZ-MOI-HISTORIQUE.md) |

## What it does

- **Sees.** A separate low-priority collector continuously samples the machine: CPU, memory, disk, services, containers, open ports, connections, logs, certificates, PHP versions, scheduled tasks, backups. It keeps the history.
- **Understands.** An anomaly is not one more alert: it correlates signals (a filling disk, a restarting service, suspicious visits) before concluding.
- **Acts, inside a cage.** Every action goes through an explicit catalogue, with guards and, where possible, a rollback: security updates, SSH hardening, service restarts (status checked afterwards), package management, banning an address or a country (never your home, your tailnet or trusted addresses), a firewall change *on trial* with automatic return, container image updates with automatic rollback, running a scan (ClamAV, Lynis, Trivy, CrowdSec).
- **Remembers.** A separate memory it consults before answering.
- **Evolves under control.** An *Evolution* tab proposes and tests variants of its own behaviour before adopting them.

**Itare**, the second agent, never touches the machine: it reads, watches and proposes, and serves each person's desk (mail, projects, calendar, documents), confined to that account's space. Accounts are partitioned: the administrator manages accounts but cannot read other people's desks.

## What it never does alone

- anything behind the master password or an explicit confirmation (purges, resets, account creation, public shares…);
- anything an outside content asks for: what it reads on the web or in an email is *data*, never an instruction;
- sending to an address that does not come from a mandate: the recipient never comes from the request.

The exact inventory is in [`V18/docs/INVENTAIRE_AUTONOMIE.md`](V18/docs/INVENTAIRE_AUTONOMIE.md).

## Secrets

Secrets live in **Vaultwarden**, the free self-hosted Bitwarden-compatible server.

## Install

On Debian 12 or Ubuntu 22.04 / 24.04, as root:

```bash
sudo bash V18/install.sh
```

Cassandra then listens on `127.0.0.1:9000`; the first-run assistant creates the administrator account and connects the AI model. See [`V18/README.md`](V18/README.md) for requirements, options, the three ways to reach it and updates.

## Contributing and security

V18 is a single file of more than 150,000 lines; it is not suited to outside contributions. **V19** is built for that (independent modules, each with its manifest, rights and tests). Report security issues privately: see [`SECURITY.md`](SECURITY.md).

## Who is behind the project

Cassandra is carried by **La Maison Bohème**, a French non-profit association (loi 1901) that accepts donations. It is an independent piece of software, not affiliated with the third-party products it can read or drive.
