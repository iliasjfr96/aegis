#!/usr/bin/env bash
# Launch the full Aegis demo: 3 target levels + API + dashboard
set -e
cd "$(dirname "$0")/.."

TARGET_LEVEL=0 .venv/bin/uvicorn aegis.targets.hr_assistant:app --port 8100 &
TARGET_LEVEL=1 .venv/bin/uvicorn aegis.targets.hr_assistant:app --port 8101 &
TARGET_LEVEL=2 .venv/bin/uvicorn aegis.targets.hr_assistant:app --port 8102 &
.venv/bin/uvicorn aegis.api.server:app --port 8200 &
(cd dashboard && npm run dev -- --port 5173) &
echo "Targets: :8100 (level 0) :8101 (level 1) :8102 (level 2)"
echo "API: :8200   Dashboard: http://localhost:5173"
wait
