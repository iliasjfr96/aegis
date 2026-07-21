#!/bin/bash
# Aegis all-in-one: ONE process serving dashboard + API + 3 demo targets
export TARGET_SIMULATED_LLM=1
export AEGIS_SCRIPTED_MODE=${AEGIS_SCRIPTED_MODE:-true}
export AEGIS_TARGET_WHITELIST=${AEGIS_TARGET_WHITELIST:-http://localhost:8000,http://127.0.0.1:8000}
export AEGIS_SECRET_KEY=${AEGIS_SECRET_KEY:-$(head -c 32 /dev/urandom | base64)}
export PORT=${PORT:-8000}

exec uvicorn aegis.api.server:app --host 0.0.0.0 --port "$PORT"
