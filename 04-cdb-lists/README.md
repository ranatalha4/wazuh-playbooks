# 04 — CDB Lists

**CDB list** = a key:value lookup file (e.g. bad IPs, bad domains, hashes). Rules check a log field against it, which is faster than writing one rule per IOC.

## Format

One entry per line, `key:value`. The value can be empty.

```
185.220.101.1:tor-exit
45.155.205.233:scanner
```
- Keys containing `:` (IPv6) must be quoted: `"2001:db8::1":bad`
- For IP ranges, the key can be a prefix: `185.220.101.` matches the whole /24 with `address_match_key`.

## Steps (on manager)

**1. Create the list.**
```bash
sudo nano /var/ossec/etc/lists/custom-malicious-ip
sudo chown wazuh:wazuh /var/ossec/etc/lists/custom-malicious-ip
sudo chmod 660 /var/ossec/etc/lists/custom-malicious-ip
```

**2. Register it.** Add this line inside `<ruleset>` in `/var/ossec/etc/ossec.conf`:
```xml
<list>etc/lists/custom-malicious-ip</list>
```

**3. Use it in a rule.** In `/var/ossec/etc/rules/local_rules.xml`:
```xml
<group name="custom_ioc,">
  <rule id="100200" level="10">
    <if_group>fortigate</if_group>
    <list field="srcip" lookup="address_match_key">etc/lists/custom-malicious-ip</list>
    <description>FortiGate: traffic from IP in custom IOC list ($(srcip))</description>
    <group>ioc,</group>
  </rule>
</group>
```

| `lookup=` | Use for |
|---|---|
| `address_match_key` | IPs / CIDR-prefix |
| `match_key` | Exact strings (domains, users, hashes) |
| `not_match_key` | Alert when value is **not** in list (allowlists) |
| `match_key_value` | Key found **and** value matches `check_value` |

**4. Test, then restart.** Lists compile automatically on restart in 4.x; no `ossec-makelists` step is needed.
```bash
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

## Verify

```bash
ls -l /var/ossec/etc/lists/custom-malicious-ip*   # a .cdb file should appear
sudo /var/ossec/bin/wazuh-logtest                 # paste a FortiGate line with a listed IP → rule 100200
```

## Updating the list later

Edit the file and restart the manager. Lists are only reloaded on restart.
For automated feeds (e.g. the FortiGate IOC feed), use a cron job that rewrites the file and restarts at a quiet hour.

## What goes in Git

| ✅ Commit | ❌ Don't commit |
|---|---|
| Public IOC lists (from public feeds) | Internal allowlists (trusted IPs, admin users) |
| Example files | Compiled `*.cdb` files (auto-generated) |

## 🔁 Cluster note

`etc/lists/` syncs from master to workers. Edit on the **master only**.
