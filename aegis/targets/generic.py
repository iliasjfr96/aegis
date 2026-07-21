"""Generic target adapter: audit ANY LLM app, not just Aegis-shaped ones.

Configure via env (per target, e.g. your own apps like ReadPlay.fr):

  AEGIS_TARGET_CHAT_PATH=/api/chat        # endpoint path (default /chat)
  AEGIS_TARGET_REQUEST_FIELD=message      # JSON field carrying the user message
  AEGIS_TARGET_RESPONSE_FIELD=reply       # JSON field (dot path) holding the reply
  AEGIS_TARGET_HEADERS=Authorization:Bearer xxx,X-Team:sec   # extra headers
  AEGIS_TARGET_HEALTH_PATH=/health        # set to empty to skip health check
"""

import json
import os

import httpx

from aegis.config import get_settings


class TargetRefusedError(Exception):
    pass


def _dig(data, dotpath: str):
    for part in dotpath.split("."):
        if isinstance(data, list):
            data = data[int(part)]
        else:
            data = data[part]
    return data


class GenericTargetClient:
    """Whitelisted HTTP client with configurable request/response mapping."""

    def __init__(self, base_url: str, transport: httpx.BaseTransport | None = None,
                 owner: str | None = None):
        from aegis.auth.scope import is_allowed

        if not is_allowed(base_url, owner):
            raise TargetRefusedError(
                f"Target {base_url} is not whitelisted or verified for this account. "
                "Refusing to scan."
            )
        s = get_settings()
        self.base_url = base_url.rstrip("/")
        self.chat_path = os.environ.get("AEGIS_TARGET_CHAT_PATH", "/chat")
        self.req_field = os.environ.get("AEGIS_TARGET_REQUEST_FIELD", "message")
        self.resp_field = os.environ.get("AEGIS_TARGET_RESPONSE_FIELD", "reply")
        self.health_path = os.environ.get("AEGIS_TARGET_HEALTH_PATH", "/health")

        headers = {}
        raw = os.environ.get("AEGIS_TARGET_HEADERS", "")
        for pair in raw.split(","):
            if ":" in pair:
                k, v = pair.split(":", 1)
                headers[k.strip()] = v.strip()

        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=s.request_timeout_s,
            transport=transport,
            headers=headers,
        )

    def health(self) -> dict:
        if not self.health_path:
            return {"status": "skipped"}
        r = self._client.get(self.health_path)
        return r.json() if r.status_code == 200 else {"status": f"http_{r.status_code}"}

    def chat(self, message: str, history: list[dict] | None = None) -> str:
        import time

        payload = {self.req_field: message}
        if history:
            payload["history"] = history
        r = None
        for attempt in range(3):  # LLM-backed targets can be slow: retry w/ backoff
            try:
                r = self._client.post(self.chat_path, json=payload)
                break
            except httpx.TimeoutException:
                if attempt == 2:
                    raise
                time.sleep(2 * (attempt + 1))
        r.raise_for_status()
        try:
            return str(_dig(r.json(), self.resp_field))
        except (KeyError, IndexError, TypeError) as e:
            raise ValueError(
                f"Could not extract '{self.resp_field}' from target response: "
                f"{json.dumps(r.json())[:200]}"
            ) from e

    def close(self):
        self._client.close()
