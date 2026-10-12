# 01 — Custom VirusTotal Integration

Sends FortiGate alerts to VirusTotal and creates a new Wazuh alert with the reputation result.

**Integration** = a script that `wazuh-integratord` runs every time an alert matches the filter you set (group, level or rule ID).

> Wazuh ships a built-in `virustotal` integration, but it only checks **file hashes from FIM** (file integrity monitoring / syscheck). This custom one checks **IPs from firewall logs**, which the built-in can't do.

## Files

| File | Goes to (on manager) |
|---|---|
| `custom-virustotal-public.py` | `/var/ossec/integrations/custom-virustotal-public.py` |
| `ossec.conf.snippet.xml` | Inside `<ossec_config>` in `/var/ossec/etc/ossec.conf` |

## Steps (on the manager, via SSH)

**1. Copy the script and set permissions.** Wazuh only runs integration scripts owned by `root:wazuh` and not writable by others.
```bash
sudo cp custom-virustotal-public.py /var/ossec/integrations/
sudo chown root:wazuh /var/ossec/integrations/custom-virustotal-public.py
sudo chmod 750 /var/ossec/integrations/custom-virustotal-public.py
```

**2. Add the config block.** Paste `ossec.conf.snippet.xml` into `/var/ossec/etc/ossec.conf` and put the real API key in `<api_key>`.
```bash
sudo nano /var/ossec/etc/ossec.conf
```

**3. Check config, then restart.** A broken `ossec.conf` stops the manager, so test it first.
```bash
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

## Verify

```bash
sudo tail -f /var/ossec/logs/ossec.log | grep -i integrat
sudo tail -f /var/ossec/logs/integrations.log
```
✅ `ossec.log` shows `wazuh-integratord` starting with no errors.

Dashboard: **☰ → Threat intelligence → Threat Hunting → Events** → filter `rule.groups: virustotal` (or whatever group the script's output rule uses).

## ⚠️ Known limitations

| Issue | Detail | Source |
|---|---|---|
| Public API rate limit | 4 requests/min, 500/day | VirusTotal public API terms (official) |
| Volume vs. quota | Filter `fortigate,firewall,traffic` matches *every traffic log* → quota exhausted quickly | Engineering estimate |
| Fix | Narrow the filter: add `<level>` or specific `<rule_id>`, or cache results in the script | Recommendation |
| Data leaves the network | Every looked-up IP is sent to VirusTotal | Check with compliance (CBUAE) |

## 🔁 Cluster note

`ossec.conf` and `/var/ossec/integrations/` **do not sync** between cluster nodes. You must copy the script and config to **every manager node** (integratord runs where the alert is generated).
