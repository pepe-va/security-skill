#!/usr/bin/env bash
set -euo pipefail

# Symlinks every skill under skills/ into the local skill directories of each agent harness:
#   ~/.claude/skills   Claude Code
#   ~/.agents/skills   Codex and other Agent Skills harnesses
# Override the destinations with SKILL_DIRS="dir1 dir2". Each entry is a symlink into this repository,
# so a `git pull` keeps the installed skills current; re-run after adding, renaming or removing a skill.

REPO="$(cd "$(dirname "$0")/.." && pwd)"
read -r -a DESTS <<< "${SKILL_DIRS:-$HOME/.claude/skills $HOME/.agents/skills}"

names=()
srcs=()
while IFS= read -r -d '' skill_md; do
  src="$(dirname "$skill_md")"
  names+=("$(basename "$src")")
  srcs+=("$src")
done < <(find "$REPO/skills" -name SKILL.md -not -path '*/node_modules/*' -print0)

for DEST in "${DESTS[@]}"; do
  # A destination that is itself a symlink into this repository would make us write links into skills/.
  if [ -L "$DEST" ]; then
    case "$(readlink -f "$DEST")" in
      "$REPO"|"$REPO"/*)
        echo "error: $DEST is a symlink into this repository; remove it and re-run." >&2
        exit 1
        ;;
    esac
  fi
  mkdir -p "$DEST"
  for i in "${!names[@]}"; do
    target="$DEST/${names[$i]}"
    if [ -e "$target" ] && [ ! -L "$target" ]; then
      echo "skip $target: exists and is not a symlink (move it away to link this skill)" >&2
      continue
    fi
    ln -sfn "${srcs[$i]}" "$target"
    echo "linked ${names[$i]} -> ${srcs[$i]} ($DEST)"
  done
done
