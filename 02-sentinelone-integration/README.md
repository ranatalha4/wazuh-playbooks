# 02 — SentinelOne Integration

Pulls SentinelOne threat data into Wazuh every minute.

**How it works:**
1. A **command wodle** (a Wazuh module that runs a command on a schedule) runs `sentinel_one.py` every 1 min.
2. The script calls the SentinelOne API and appends events to `/var/log/sentinelone.json`.
3. A **localfile** block (tells Wazuh which log file to read) ingests that file as JSON.

## Files

| File | Goes to (on manager) |
|---|---|
| `sentinel_one.py` | `/var/ossec/integrations/sentinel_one.py` |
| `ossec.conf.snippet.xml` | Inside `<ossec_config>` in `/var/ossec/etc/ossec.conf` |
| `template-sentinelone_final.json` | Indexer composable template (already applied) |

## Steps (on the manager)

**1. Store the API token outside the script.** Keeps the token out of Git and out of `ps` output.
```bash
echo 'S1_API_TOKEN=<your-token>' | sudo tee /var/ossec/etc/sentinelone.env >/dev/null
sudo chown root:root /var/ossec/etc/sentinelone.env
sudo chmod 600 /var/ossec/etc/sentinelone.env
```
In `sentinel_one.py`, read it with `os.environ` or by parsing that file. No token in the code.

**2. Copy the script.**
```bash
sudo cp sentinel_one.py /var/ossec/integrations/
sudo chown root:wazuh /var/ossec/integrations/sentinel_one.py
sudo chmod 750 /var/ossec/integrations/sentinel_one.py
```

**3. Add the config block**, then test and restart.
```bash
sudo nano /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

## Verify

```bash
sudo tail -f /var/log/sentinelone.json          # new lines every ~1 min
sudo grep -i sentinel /var/ossec/logs/ossec.log # localfile picked up, no errors
```
Dashboard: **☰ → Threat intelligence → Threat Hunting → Events** → filter `location: /var/log/sentinelone.json`.

## ⚠️ Gotchas

| Issue | Fix |
|---|---|
| Overview dashboard shard failures | `sentinelone_final` template overrides the legacy `wazuh` template **with no merging**. It must map `manager.name` as `keyword`. Any new field not mapped there can break again. Permanent fix: template composition via `composed_of`. |
| After any template change | Refresh the index pattern: **☰ → Dashboard management → Dashboards Management → Index patterns → wazuh-alerts-\* → 🔄 Refresh fields** |
| `<timeout>0</timeout>` | Means *no timeout*. If the S1 API hangs, the run never ends. Set e.g. `50` (seconds, below the 1-min interval). |
| `/var/log/sentinelone.json` grows forever | Add a logrotate rule (daily, keep 7, `copytruncate`). |
| Duplicate events | Script must track the last-pulled timestamp, otherwise every run re-ingests old events. |

## 🔁 Cluster note

Run this wodle on the **master node only**. On every node it would pull the same events N times.
