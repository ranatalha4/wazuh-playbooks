#!/usr/bin/env bash
# leak-check.sh — fail if the repo contains internal IPs, credentials, keys or company names.
# Run from the repo root before every push:  ./scripts/leak-check.sh
# Lines whose value is a placeholder (REDACTED, <...>) are allowed.
# Company and internal names are NOT stored in this repo. Put them in an untracked
# .leakcheck.local at the repo root (see README), or pass them as env vars:
#   COMPANY='acme|acmecorp'  EXTRA='siem01|corp\.local'  ./scripts/leak-check.sh
# In CI, set COMPANY as a repository secret.
set -u

[ -f .leakcheck.local ] && . ./.leakcheck.local
COMPANY="${COMPANY:-}"
EXTRA="${EXTRA:-}"

PATTERN='(^|[^0-9])(10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)'
# credential assignments with a real-looking value: quoted (>=4 chars) or bare long token (>=20 chars)
PATTERN="$PATTERN"'|(password|passwd|secret|token|api[_-]?key)["'"'"']?[[:space:]]*[:=][[:space:]]*(["'"'"'][^"'"'"'<$ ]{4,}|[A-Za-z0-9_+/=-]{20,})'
# XML credential tags with any value (e.g. <api_key>abc</api_key> in ossec.conf)
PATTERN="$PATTERN"'|<(api_key|password|token|key)>[^<]+</'
PATTERN="$PATTERN"'|BEGIN [A-Z ]*PRIVATE KEY'
[ -n "$COMPANY" ] && PATTERN="$PATTERN|$COMPANY"
[ -n "$EXTRA" ] && PATTERN="$PATTERN|$EXTRA"

# Placeholders that are safe
ALLOW='REDACTED|<(your|org|real|INTERNAL)[A-Za-z_ -]*>'

hits=$(grep -rniE --exclude-dir=.git --exclude-dir=.github \
        --exclude=leak-check.sh --exclude=collect.sh --exclude=.leakcheck.local "$PATTERN" . | grep -vE "$ALLOW" || true)

if [ -n "$hits" ]; then
  echo "$hits"
  echo "LEAK CHECK FAILED: review the lines above before pushing." >&2
  exit 1
fi
echo "Leak check passed."
