#!/usr/bin/env bash
# leak-check.sh — fail if the repo contains internal IPs, credentials, keys or company names.
# Run from the repo root before every push:  ./scripts/leak-check.sh
# Lines whose value is a placeholder (REDACTED, <...>) are allowed.
# Add more internal names via EXTRA (pipe-separated), e.g. EXTRA='siem01|corp\.local'
set -u

COMPANY="${COMPANY:-}"
EXTRA="${EXTRA:-}"

PATTERN='(^|[^0-9])(10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)'
PATTERN="$PATTERN"'|(password|passwd|secret|token|api[_-]?key)["'"'"']?[[:space:]]*[:=]'
PATTERN="$PATTERN"'|BEGIN [A-Z ]*PRIVATE KEY'
PATTERN="$PATTERN|$COMPANY"
[ -n "$EXTRA" ] && PATTERN="$PATTERN|$EXTRA"

# Placeholders that are safe
ALLOW='REDACTED|<[A-Za-z_ -]+>|INTERNAL_(IP|HOST)'

hits=$(grep -rniE --exclude-dir=.git --exclude-dir=.github \
        --exclude=leak-check.sh --exclude=collect.sh "$PATTERN" . | grep -vE "$ALLOW" || true)

if [ -n "$hits" ]; then
  echo "$hits"
  echo "LEAK CHECK FAILED: review the lines above before pushing." >&2
  exit 1
fi
echo "Leak check passed."
