#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=${1:-$(cd "$(dirname "$0")/.." && pwd)}
EXCLUDES=(--exclude-dir=.git --exclude=privacy-audit.sh --exclude='*.png' --exclude='*.jpg' --exclude='*.jpeg' --exclude='*.gif' --exclude='*.webp')
FAIL=0
check(){ local label=$1 pattern=$2; local out; out=$(grep -RIn --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.git --exclude-dir=__pycache__ "${EXCLUDES[@]}" "$pattern" "$ROOT" || true); if [[ -n $out ]]; then echo "[$label]"; echo "$out"; FAIL=1; fi; }
check 'private identity values' 'sectorpace\.com|149\.248\.|163\.192\.'
check 'OCI credential material' 'ocid1\.[A-Za-z0-9._-]{12,}|OCI-Token-Secret|SMTP_USERNAME_PLACEHOLDER'
check 'private key blocks' 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY'
if ((FAIL)); then echo 'Privacy audit failed.'; exit 1; fi
echo 'Privacy audit passed.'
