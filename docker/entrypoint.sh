#!/usr/bin/env bash
set -euo pipefail

SKILL_DIR="/audit/skill"
RESULT_DIR="/audit/results"
mkdir -p "$RESULT_DIR"

EXECUTED_LIST="$RESULT_DIR/executed_scripts.txt"
: > "$EXECUTED_LIST"

while IFS= read -r script; do
  rel="${script#${SKILL_DIR}/}"
  base="$(echo "$rel" | tr '/ ' '__')"

  case "$script" in
    *.sh)
      runner=(bash "$script")
      ;;
    *.py)
      runner=(python3 "$script")
      ;;
    *.js)
      if command -v node >/dev/null 2>&1; then
        runner=(node "$script")
      else
        echo "skip:$rel (node missing)" >> "$RESULT_DIR/skipped.txt"
        continue
      fi
      ;;
    *)
      continue
      ;;
  esac

  echo "$rel" >> "$EXECUTED_LIST"

  timeout 30s strace -ff \
    -e trace=open,openat,connect,execve \
    -o "$RESULT_DIR/${base}.strace" \
    "${runner[@]}" \
    >"$RESULT_DIR/${base}.stdout" \
    2>"$RESULT_DIR/${base}.stderr" || true

done < <(find "$SKILL_DIR" -type f \( -name "*.sh" -o -name "*.py" -o -name "*.js" \) | sort)
