#!/bin/sh

set -e

echo "Starting SoSync Companion..."

mkdir -p /data/cloudflared

if [ -z "${SOSYNC_BACKEND_SIGNING_PUBLIC_KEY:-}" ] && [ -f /data/options.json ]; then
  SOSYNC_BACKEND_SIGNING_PUBLIC_KEY="$(python3 - <<'PY'
import json

try:
    with open("/data/options.json", "r", encoding="utf-8") as file:
        print(str(json.load(file).get("backend_signing_public_key") or "").strip())
except Exception:
    print("")
PY
)"
  export SOSYNC_BACKEND_SIGNING_PUBLIC_KEY
fi

if [ -n "${SOSYNC_BACKEND_SIGNING_PUBLIC_KEY:-}" ]; then
  echo "Backend signing public key configured."
else
  echo "Backend signing public key not configured."
fi

echo "Starting SoSync API on port 8765..."

exec python3 -u - <<'PY'
import runpy
import sys
import traceback

print("[SOSYNC-E2EE-COMPANION] processEntrypoint", flush=True)
try:
    runpy.run_path("/app/app.py", run_name="__main__")
except Exception as error:
    print(
        f"[SOSYNC-E2EE-COMPANION] fatalStartupError type={type(error).__name__} message={error}",
        flush=True
    )
    traceback.print_exc()
    sys.exit(1)
PY
