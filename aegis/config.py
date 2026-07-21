"""Central configuration for Aegis.

Everything safety-critical lives here: the target whitelist is the hard
boundary of the tool - Aegis refuses to attack anything not listed.
"""

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="AEGIS_", extra="ignore")

    llm_provider: str = "ollama"  # "ollama" | "openai" | "anthropic" | "kimi"
    attack_model: str = "llama3.1:8b"
    judge_model: str = "llama3.1:8b"

    # Hard safety scope - comma-separated in .env
    target_whitelist: str = "http://localhost:8100"

    # Zero-AI demo mode: scripted openers only + heuristic judge
    scripted_mode: bool = False

    # Attack budget guardrails
    max_turns_per_attack: int = 6
    max_total_requests: int = 200
    request_timeout_s: float = 15.0

    @field_validator("llm_provider")
    @classmethod
    def _check_provider(cls, v: str) -> str:
        if v not in {"openai", "anthropic", "ollama", "kimi"}:
            raise ValueError(f"Unsupported provider: {v}")
        return v

    @property
    def allowed_targets(self) -> list[str]:
        return [t.strip().rstrip("/") for t in self.target_whitelist.split(",") if t.strip()]

    def is_target_allowed(self, url: str) -> bool:
        url = url.rstrip("/")
        return any(url == allowed or url.startswith(allowed + "/") for allowed in self.allowed_targets)


@lru_cache
def get_settings() -> Settings:
    return Settings()

# --- Zero-AI demo mode extensions (monkey-patch friendly) ---
