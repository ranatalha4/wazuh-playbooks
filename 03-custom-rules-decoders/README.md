# 03 — Custom Rules & Decoders

- **Decoder** = extracts fields (srcip, user, command…) from a raw log line.
- **Rule** = matches decoded fields and decides whether to raise an alert, and at what level.

## Where they live (manager)

| Type | Custom (ours, put here) | Default (Wazuh, never edit) |
|---|---|---|
| Rules | `/var/ossec/etc/rules/` | `/var/ossec/ruleset/rules/` |
| Decoders | `/var/ossec/etc/decoders/` | `/var/ossec/ruleset/decoders/` |

Default files get overwritten on upgrade. Always work in `etc/`.

## Rule ID ranges

| Range | Use |
|---|---|
| 100000–120000 | Custom rules (ours) |
| Everything else | Reserved by Wazuh |

## Steps

**1. Add or edit the file.**
```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 660 /var/ossec/etc/rules/local_rules.xml
```
Same ownership and permissions for files in `etc/decoders/`.

**2. Test with a real log line, before restarting.** `wazuh-logtest` runs the full decode → rule chain on a sample line with no impact on production.
```bash
sudo /var/ossec/bin/wazuh-logtest
```
Paste a log line. Check:
- **Phase 2:** decoder name and fields
- **Phase 3:** rule ID and level

**3. Check syntax, then restart.**
```bash
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```
⚠️ A broken XML file stops `wazuh-analysisd`, and then **no alerts are generated**. Always run `-t` first.

## Verify

```bash
sudo grep -iE 'error|critical' /var/ossec/logs/ossec.log | tail
```
Dashboard: **☰ → Threat intelligence → Threat Hunting → Events** → filter `rule.id: <your id>`.

## Our custom content

| File | Purpose |
|---|---|
| `decoders/` | Includes the PCRE2 decoder for syslog-wrapped auditd lines (agentless `monitoring` host) |
| `rules/` | Local rules |

> Agent-forwarded auditd events don't need it; the built-in decoder handles them.

## Before committing

- Replace internal IPs and hostnames in `<match>`, `<regex>` and `<field>` with placeholders.
- Remove allowlist rules that reveal trusted users or IPs.

## 🔁 Cluster note

`etc/rules`, `etc/decoders` and `etc/lists` **sync automatically from master to workers**. Edit them on the **master only**.
