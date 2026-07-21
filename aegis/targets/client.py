"""HTTP client used by attack agents to talk to the target.

Hard rule: the whitelist is enforced HERE, at the network boundary,
so no agent can ever reach a non-approved target - even if an LLM
hallucinates a different URL.

TargetClient = generic adapter (env-configurable endpoint/fields/headers),
so Aegis can audit any LLM app, not just its built-in demo target.
"""

from aegis.targets.generic import GenericTargetClient, TargetRefusedError

TargetClient = GenericTargetClient

__all__ = ["TargetClient", "TargetRefusedError"]
