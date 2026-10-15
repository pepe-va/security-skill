#!/usr/bin/env bash
set -euo pipefail

# Lists every SKILL.md in the repository, relative to its root.
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
find skills -name SKILL.md -not -path '*/node_modules/*' | sort
