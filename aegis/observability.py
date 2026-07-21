"""Langfuse observability: every graph node emits a trace + span.

Active when LANGFUSE_PUBLIC_KEY/SECRET_KEY are set (env or docker-compose);
otherwise a transparent no-op so the tool runs standalone.
"""

import os
from functools import wraps

_lf = None
_checked = False


def get_langfuse():
    global _lf, _checked
    if _checked:
        return _lf
    _checked = True
    if os.environ.get("LANGFUSE_PUBLIC_KEY"):
        from langfuse import Langfuse

        _lf = Langfuse()
    return _lf


def traced(node_name: str):
    """Wrap a graph node: creates a Langfuse trace per audit + span per call."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(state):
            lf = get_langfuse()
            if lf is None:
                return fn(state)
            trace = lf.trace(
                name="aegis-audit",
                metadata={"target_url": state.get("target_url")},
                tags=["aegis", node_name],
            )
            span = trace.span(name=node_name, input={"status": state.get("status")})
            try:
                out = fn(state)
                span.end(
                    output={
                        "status": out.get("status"),
                        "findings": len(out.get("findings", [])),
                        "attempts": len(out.get("attempts", [])),
                        "requests_used": out.get("requests_used"),
                    }
                )
                return out
            except Exception as e:
                span.end(level="ERROR", status_message=str(e))
                raise

        return wrapper

    return decorator
