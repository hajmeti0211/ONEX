#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${ONEX_APP_DIR:-/opt/onex}"
REPO="${ONEX_REPO:-}"
PORT="${PORT:-8000}"
PYTHON="${PYTHON_BIN:-python3}"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root, or set ONEX_APP_DIR to a writable directory." >&2
  exit 1
fi

command -v git >/dev/null || { echo "git is required"; exit 1; }
command -v "$PYTHON" >/dev/null || { echo "python3 is required"; exit 1; }

mkdir -p "$APP_DIR" "$APP_DIR/data"
if [[ -n "$REPO" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  git clone --depth 1 "$REPO" "$tmp/src"
  rsync -a --delete --exclude data/ "$tmp/src/" "$APP_DIR/"
fi

cd "$APP_DIR"
"$PYTHON" -m venv .venv
".venv/bin/python" -m pip install --upgrade pip
".venv/bin/pip" install --no-cache-dir -r requirements.txt

cat > "$APP_DIR/.env" <<EOF
PORT=$PORT
DATA_DIR=$APP_DIR/data
PYTHONUNBUFFERED=1
EOF
chmod 600 "$APP_DIR/.env"

exec env $(tr '\n' ' ' < "$APP_DIR/.env") \
  "$APP_DIR/.venv/bin/python" main.py
