"""Per-scan LLM override via contextvars: a user's own provider/key is
resolved at scan launch and flows into the LLM factory for that scan only.
"""

from contextvars import ContextVar

SCAN_LLM: ContextVar[dict | None] = ContextVar("scan_llm", default=None)
