# 01 — Custom VirusTotal IP Integration

Checks the **public IP** in FortiGate alerts against VirusTotal and raises a new Wazuh alert when it's suspicious or malicious.

**Integration** = a script that `wazuh-integratord` runs for every alert matching the filter in `ossec.conf` (group, level or rule ID).

> The built-in `virustotal` integration only checks **file hashes from FIM** (file integrity monitoring). This one checks **IPs from firewall logs**.

## How it works

```
FortiGate alert (level ≥ 8, group fortigate/firewall/traffic)
  → integratord → custom-virustotal-ip (wrapper) → custom-virustotal-ip.py
      → private IP? skip
      → in cache (24 h)? use cached result
      → rate limit OK (4/min, 500/day)? call VirusTotal API v3
  → suspicious/malicious → event back to Wazuh → rule 100303 / 100304
```

## Files

| File | Goes to (on manager) | Owner / mode |
|---|---|---|
| `custom-virustotal-ip.py` | `/var/ossec/integrations/` | `root:wazuh` 750 |
| wrapper `custom-virustotal-ip` | `/var/ossec/integrations/` (copy of stock `virustotal` wrapper) | `root:wazuh` 750 |
| `custom_virustotal_rules.xml` | `/var/ossec/etc/rules/` | `wazuh:wazuh` 660 |
| `ossec.conf.snippet.xml` | Inside `<ossec_config>` in `/var/ossec/etc/ossec.conf` | — |
| `sample-alert.json` | Test input only | — |

## Rules

| ID | Level | Fires when |
|---|---|---|
| 100300 | 0 | Any result from this integration (parent) |
| 100301 | 3 | Clean (only emitted in test mode) |
| 100302 | 3 | IP not in VirusTotal (only emitted in test mode) |
| 100303 | 8 | 1–2 engines malicious, or any suspicious |
| 100304 | 12 | ≥ 3 engines malicious |

The thresholds are an engineering choice to cut single-engine false positives; tune `MALICIOUS_MIN` in the script.

## Install (on the manager)

**1. Back up `ossec.conf`.** If an edit breaks it, the manager won't start.
```bash
sudo cp -p /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-$(date +%F)
```

**2. Install the script, wrapper and rules.** The wrapper is a copy of Wazuh's stock one; it runs `<its-own-name>.py` with Wazuh's bundled Python.
```bash
sudo install -o root -g wazuh -m 750 custom-virustotal-ip.py /var/ossec/integrations/
sudo cp /var/ossec/integrations/virustotal /var/ossec/integrations/custom-virustotal-ip
sudo chown root:wazuh /var/ossec/integrations/custom-virustotal-ip && sudo chmod 750 /var/ossec/integrations/custom-virustotal-ip
sudo install -o wazuh -g wazuh -m 660 custom_virustotal_rules.xml /var/ossec/etc/rules/
sudo install -d -o wazuh -g wazuh -m 750 /var/ossec/var/custom-vt
```

**3. Edit the `<integration>` block** in `/var/ossec/etc/ossec.conf` to match `ossec.conf.snippet.xml`, with the real API key.

**4. Validate, then restart.**
```bash
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

## Verify

**Integratord is running:**
```bash
ps aux | grep [i]ntegratord
```

**Rules load and match.** Run `sudo /var/ossec/bin/wazuh-logtest` and paste:
```
{"integration":"custom-virustotal-ip","vt":{"ip":"203.0.113.5","verdict":"malicious","malicious":"7","suspicious":"0"}}
```
✅ Phase 3 shows rule **100304**, level 12.

**End-to-end with a real lookup.** Uses the sample alert and the clean test mode; the key is read silently, not stored in shell history.
```bash
read -rsp "VT API key: " VTKEY; echo
sudo -u wazuh env CUSTOM_VT_EMIT_CLEAN=1 /var/ossec/integrations/custom-virustotal-ip sample-alert.json "$VTKEY" "" debug
unset VTKEY
sudo tail -5 /var/ossec/logs/integrations.log
```
✅ Log shows `looked up 8.8.8.8: clean` and `event sent`.

**Dashboard:** ☰ → Threat intelligence → Threat Hunting → Events → filter `rule.groups: custom_virustotal`.

## ⚠️ Known limitations

| Issue | Detail | Source |
|---|---|---|
| Public API rate limit | 4 req/min, 500/day; script stops calling when reached and logs `rate limit reached` | VirusTotal public API (official) |
| Only alerts ≥ level 8 are checked | `<log_alert_level>8` controls what reaches integratord | Wazuh behaviour |
| Needs FortiGate alerts flowing | No FortiGate alerts → no lookups | — |
| Data leaves the network | Public IPs only are sent to VirusTotal | Check with compliance (CBUAE) |
| API key visible in process list | Integratord passes it as an argument (Wazuh design) | Wazuh behaviour |

## 🔁 Cluster note

`ossec.conf`, `/var/ossec/integrations/` and `/var/ossec/var/custom-vt/` **do not sync** between nodes. Install on **every manager node**; each node keeps its own cache and its own rate counter, so lower `RATE_PER_MIN` per node to share the quota. The rules file in `etc/rules/` **does** sync from the master.
