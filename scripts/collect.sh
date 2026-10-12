#!/usr/bin/env bash
# collect.sh — copy custom Wazuh files from the manager into this repo and redact them.
#
# WHERE:  run on the Wazuh manager, from inside the repo folder.
# HOW:    sudo ./scripts/collect.sh
# SAFE:   read-only on Wazuh. It only copies files OUT of /var/ossec; nothing is changed there.
#
# AFTER RUNNING (mandatory):
#   1. Review every file:  git diff   (or read each new file)
#   2. Scan:               gitleaks detect --source . --no-git -v
#   3. Commit one folder at a time.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OSSEC=/var/ossec

if [[ $EUID -ne 0 ]]; then echo "Run with sudo"; exit 1; fi

# ---------- 01 VirusTotal ----------
cp "$OSSEC/integrations/custom-virustotal-public.py" "$REPO/01-virustotal-integration/" 2>/dev/null \
  || echo "WARN: custom-virustotal-public.py not found"

# ---------- 02 SentinelOne ----------
cp "$OSSEC/integrations/sentinel_one.py" "$REPO/02-sentinelone-integration/" 2>/dev/null \
  || echo "WARN: sentinel_one.py not found"

# Export the index template (prompts for the admin password, kept out of shell history)
read -rp "Export sentinelone_final template from indexer? [y/N] " ans
if [[ "${ans,,}" == "y" ]]; then
  curl -sk -u admin https://127.0.0.1:9200/_index_template/sentinelone_final \
    > "$REPO/02-sentinelone-integration/template-sentinelone_final.json"
fi

# ---------- 03 Rules & decoders (custom only: /var/ossec/etc, NOT ruleset/) ----------
cp "$OSSEC"/etc/rules/*.xml    "$REPO/03-custom-rules-decoders/rules/"    2>/dev/null || true
cp "$OSSEC"/etc/decoders/*.xml "$REPO/03-custom-rules-decoders/decoders/" 2>/dev/null || true

# ---------- 04 CDB lists (custom only; skip Wazuh defaults and compiled .cdb) ----------
mkdir -p "$REPO/04-cdb-lists/lists"
find "$OSSEC/etc/lists" -maxdepth 1 -type f ! -name '*.cdb' \
  ! -name 'audit-keys' ! -name 'security-eventchannel' \
  -exec cp {} "$REPO/04-cdb-lists/lists/" \;

# ---------- Redaction pass ----------
echo "Redacting..."
find "$REPO" -type f \( -name '*.py' -o -name '*.xml' -o -name '*.json' -o -name '*.conf' \) \
  ! -path '*/.git/*' -print0 | while IFS= read -r -d '' f; do
  sed -i -E \
    -e 's#(<api_key>)[^<]*(</api_key>)#\1REDACTED\2#g' \
    -e 's#((api_?key|apikey|api_?token|token|secret|password|passwd)[[:space:]]*[:=][[:space:]]*["'"'"'])[^"'"'"']+(["'"'"'])#\1REDACTED\4#Ig' \
    -e 's#Authorization:[[:space:]]*(ApiToken|Bearer|Basic)[[:space:]]+[A-Za-z0-9._=+/-]+#Authorization: \1 REDACTED#Ig' \
    -e 's#\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b#<INTERNAL_IP>#g' \
    -e 's#\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b#<INTERNAL_IP>#g' \
    -e 's#\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b#<INTERNAL_IP>#g' \
    -e 's#[A-Za-z0-9.-]*example\.(ae|cr)\b#<INTERNAL_HOST>#Ig' \
    "$f"
done

# Fix ownership so you can git-add as your normal user
chown -R "${SUDO_USER:-root}:${SUDO_USER:-root}" "$REPO"

echo
echo "Done. NOW:"
echo "  1) Review every file manually (redaction is pattern-based, not perfect)"
echo "  2) grep -rniE 'key|token|secret|passw' $REPO --exclude-dir=.git"
echo "  3) gitleaks detect --source $REPO --no-git -v"
