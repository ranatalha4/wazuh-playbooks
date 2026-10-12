#!/usr/bin/env python3
"""
custom-virustotal-ip.py — Wazuh 4.14.0 integration
Checks the public IP in FortiGate alerts against VirusTotal (API v3) and sends
the verdict back to Wazuh as a new event (matched by custom_virustotal_rules.xml).

Called by wazuh-integratord through the wrapper /var/ossec/integrations/custom-virustotal-ip:
    argv[1] = path to the alert JSON file
    argv[2] = <api_key> from ossec.conf
    argv[3] = <hook_url> (unused)
    argv[4] = "debug" when integrator debug is enabled (optional)

Protections:
  * Only public (global) IPs are looked up — private/internal IPs never leave the network.
  * SQLite cache (default 24 h) so the same IP is not looked up twice.
  * Rate limiter shared by all concurrent runs (public API: 4 req/min, 500 req/day).
  * Re-alert suppression: a cached bad IP raises at most one event per hour.
  * The API key is never written to the log.
"""
import ipaddress
import json
import os
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ---------------- Settings ----------------
INTEGRATION = "custom-virustotal-ip"
WAZUH = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
LOG_FILE = os.path.join(WAZUH, "logs", "integrations.log")
QUEUE_SOCKET = os.path.join(WAZUH, "queue", "sockets", "queue")
CACHE_DB = os.path.join(WAZUH, "var", "custom-vt", "cache.db")

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
VT_TIMEOUT = 10            # seconds per API call

CACHE_TTL = 24 * 3600      # reuse a lookup for 24 h
REALERT_AFTER = 3600       # cached bad IP: re-alert at most once per hour
RATE_PER_MIN = 4           # VirusTotal public API limit (official)
RATE_PER_DAY = 500         # VirusTotal public API limit (official)

MALICIOUS_MIN = 3          # >= 3 engines flag malicious -> "malicious" (engineering choice)
IP_FIELDS = ("srcip", "dstip")   # FortiGate decoder fields, checked in this order

EMIT_CLEAN = os.environ.get("CUSTOM_VT_EMIT_CLEAN") == "1"   # testing only
DEBUG = False


class QuotaExceeded(Exception):
    pass


# ---------------- Helpers ----------------
def log(msg, debug_only=False):
    if debug_only and not DEBUG:
        return
    ts = datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{ts} {INTEGRATION}: {msg}\n")
    except OSError:
        pass


def open_db():
    os.makedirs(os.path.dirname(CACHE_DB), exist_ok=True)
    conn = sqlite3.connect(CACHE_DB, timeout=15, isolation_level=None)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ip_cache ("
        " ip TEXT PRIMARY KEY, ts INTEGER, result TEXT, last_alert INTEGER DEFAULT 0)"
    )
    conn.execute("CREATE TABLE IF NOT EXISTS requests (ts INTEGER)")
    return conn


def pick_ip(alert):
    """Return the first public IP found in the alert's data fields, else None."""
    data = alert.get("data") or {}
    for field in IP_FIELDS:
        value = data.get(field)
        if not value:
            continue
        try:
            ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        if ip.is_global:
            return str(ip)
    return None


def take_rate_slot(conn):
    """Reserve one API call if under the per-minute and per-day limits. Safe across processes."""
    now = int(time.time())
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM requests WHERE ts < ?", (now - 86400,))
        per_min = conn.execute("SELECT COUNT(*) FROM requests WHERE ts >= ?", (now - 60,)).fetchone()[0]
        per_day = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        if per_min >= RATE_PER_MIN or per_day >= RATE_PER_DAY:
            conn.execute("COMMIT")
            return False, per_min, per_day
        conn.execute("INSERT INTO requests (ts) VALUES (?)", (now,))
        conn.execute("COMMIT")
        return True, per_min + 1, per_day + 1
    except Exception:
        conn.execute("ROLLBACK")
        raise


def vt_lookup(ip, api_key):
    req = urllib.request.Request(VT_URL + ip, headers={"x-apikey": api_key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=VT_TIMEOUT) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False}
        if e.code == 429:
            raise QuotaExceeded("VirusTotal returned 429 (quota exceeded)")
        if e.code == 401:
            raise RuntimeError("VirusTotal returned 401 (invalid API key)")
        raise RuntimeError(f"VirusTotal HTTP {e.code}")
    attrs = (body.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    return {
        "found": True,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "reputation": attrs.get("reputation"),
        "country": attrs.get("country"),
        "as_owner": attrs.get("as_owner"),
    }


def verdict_of(result):
    if not result.get("found"):
        return "unknown"
    if result["malicious"] >= MALICIOUS_MIN:
        return "malicious"
    if result["malicious"] > 0 or result["suspicious"] > 0:
        return "suspicious"
    return "clean"


def send_event(event):
    msg = f"1:{INTEGRATION}:{json.dumps(event)}"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.connect(QUEUE_SOCKET)
        sock.send(msg.encode())
    finally:
        sock.close()


# ---------------- Main ----------------
def main(argv):
    global DEBUG
    if len(argv) < 3:
        log("bad arguments; expected <alert_file> <api_key> [hook_url] [debug]")
        return 1
    DEBUG = len(argv) > 4 and argv[4] == "debug"
    alert_file, api_key = argv[1], argv[2]

    with open(alert_file) as f:
        alert = json.load(f)

    ip = pick_ip(alert)
    if not ip:
        log(f"no public IP in alert {alert.get('id')} — skipped", debug_only=True)
        return 0

    now = int(time.time())
    conn = open_db()
    row = conn.execute("SELECT ts, result, last_alert FROM ip_cache WHERE ip = ?", (ip,)).fetchone()

    if row and now - row[0] < CACHE_TTL:
        result, last_alert, cached = json.loads(row[1]), row[2] or 0, True
    else:
        ok, per_min, per_day = take_rate_slot(conn)
        if not ok:
            log(f"rate limit reached ({per_min}/min, {per_day}/day) — skipped {ip}")
            return 0
        try:
            result = vt_lookup(ip, api_key)
        except QuotaExceeded as e:
            log(str(e))
            return 0
        last_alert, cached = 0, False
        conn.execute(
            "INSERT INTO ip_cache (ip, ts, result, last_alert) VALUES (?, ?, ?, 0) "
            "ON CONFLICT(ip) DO UPDATE SET ts = excluded.ts, result = excluded.result",
            (ip, now, json.dumps(result)),
        )
        log(f"looked up {ip}: {verdict_of(result)} ({per_min}/min, {per_day}/day used)", debug_only=True)

    verdict = verdict_of(result)

    if verdict in ("clean", "unknown") and not EMIT_CLEAN:
        return 0
    if cached and now - last_alert < REALERT_AFTER and not EMIT_CLEAN:
        log(f"{ip} ({verdict}) already alerted recently — suppressed", debug_only=True)
        return 0

    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    event = {
        "integration": INTEGRATION,
        "vt": {
            "ip": ip,
            "verdict": verdict,
            "found": result.get("found", False),
            "malicious": result.get("malicious", 0),
            "suspicious": result.get("suspicious", 0),
            "harmless": result.get("harmless", 0),
            "undetected": result.get("undetected", 0),
            "reputation": result.get("reputation"),
            "country": result.get("country"),
            "as_owner": result.get("as_owner"),
            "cached": cached,
            "permalink": f"https://www.virustotal.com/gui/ip-address/{ip}",
        },
        "original": {
            "alert_id": alert.get("id"),
            "rule_id": rule.get("id"),
            "rule_description": rule.get("description"),
            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "srcip": data.get("srcip"),
            "dstip": data.get("dstip"),
        },
    }
    send_event(event)
    conn.execute("UPDATE ip_cache SET last_alert = ? WHERE ip = ?", (now, ip))
    log(f"event sent for {ip}: {verdict}", debug_only=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:  # never crash integratord; log without secrets
        log(f"error: {type(exc).__name__}: {exc}")
        sys.exit(1)
