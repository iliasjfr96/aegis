import os

# Deterministic settings for tests, no .env needed
os.environ.setdefault("AEGIS_TARGET_WHITELIST", "http://localhost:8100")
