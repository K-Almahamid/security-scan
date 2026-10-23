#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${HOME}/.cursor/skills"
mkdir -p "${DEST}/security-scan" "${DEST}/security-scan-source-audit"
cp "${ROOT}/skill/security-scan/SKILL.md" "${DEST}/security-scan/SKILL.md"
cp "${ROOT}/skill/security-scan-source-audit/SKILL.md" "${DEST}/security-scan-source-audit/SKILL.md"
echo "Synced skills to ${DEST}"
