# Wazuh Playbooks

Practical how-to guides and redacted configs for running Wazuh in production: third-party integrations, custom detections and IOC lookups, with a redaction pipeline and CI checks that keep secrets and internal data out of the repo.

> **Version:** Wazuh **4.14.0**, all-in-one (manager + indexer + dashboard on one host).
> Paths and commands are for 4.14.0. Anything that changes in a multi-node cluster is marked **🔁 Cluster note**.

## Guides

| # | Folder | What it covers | Status |
|---|---|---|---|
| 01 | [virustotal-integration](01-virustotal-integration/) | Custom VirusTotal IP lookup on FortiGate alerts | ✅ Script + rules written and tested (mocked API); server deployment pending |
| 02 | [sentinelone-integration](02-sentinelone-integration/) | Pulling SentinelOne threats into Wazuh | 📝 Guide done; live script to be added (redacted) |
| 03 | [custom-rules-decoders](03-custom-rules-decoders/) | Writing, testing and deploying custom rules/decoders | 📝 Guide done; live rules/decoders to be added |
| 04 | [cdb-lists](04-cdb-lists/) | Adding CDB lists (IOC lookups) and using them in rules | 📝 Guide done; example list included |

## Rules for this repo

- **No secrets.** API keys, tokens, passwords, certs, `client.keys`, `internal_users.yml` never get committed.
- **No real data.** No alerts, archives or log files.
- Internal IPs and hostnames are replaced with `<INTERNAL_IP>` / `<INTERNAL_HOST>`.
- One folder per commit. Run `gitleaks` before every commit.

## Refreshing files from the server

On the Wazuh manager, from the repo root:
```bash
sudo ./scripts/collect.sh     # copies live files out of /var/ossec and redacts them
./scripts/leak-check.sh       # must pass before commit
```
Redaction is pattern-based. **It does not replace a manual review.**

Company names and internal domains are never stored in the repo. Put them in an untracked `.leakcheck.local` at the repo root (it is gitignored):
```bash
COMPANY='yourcompany|yourbrand'           # names the leak check must catch
INTERNAL_DOMAINS='corp\.example|example\.local'   # domains collect.sh replaces with <INTERNAL_HOST>
```

## CI checks (every push)

| Check | Fails when |
|---|---|
| XML / JSON validity | A rule, decoder, snippet or template is malformed |
| Rule IDs | Duplicate IDs, or IDs outside 100000–120000 |
| ShellCheck | Script errors in `scripts/` |
| Leak check | Internal IPs, credentials or company names found |
| Gitleaks | Any secret anywhere in Git history |
