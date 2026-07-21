"""Provider-agnostic chat model factory.

Swap providers with AEGIS_LLM_PROVIDER in .env - the rest of the codebase
never imports provider SDKs directly.
Providers: ollama (local, free) | kimi (Kimi Code subscription) |
           openai | anthropic.
"""

from dotenv import load_dotenv
from langchain_core.language_models.chat_models import BaseChatModel

from aegis.config import get_settings

load_dotenv()  # make provider keys from .env visible to os.environ


def get_chat_model(role: str = "attack", temperature: float = 0.7) -> BaseChatModel:
    """role: "attack" (cheap/fast, high volume) | "judge" (stronger, deterministic).

    Resolution order: per-scan user override (BYOK) -> global .env settings.
    """
    from aegis.auth.context import SCAN_LLM

    override = SCAN_LLM.get()
    if override:
        model = override.get(f"{role}_model") or override.get("model", "")
        return _build(override["provider"], model, override.get("api_key"),
                      0.0 if role == "judge" else temperature)

    s = get_settings()
    model = s.judge_model if role == "judge" else s.attack_model
    temp = 0.0 if role == "judge" else temperature
    return _build(s.llm_provider, model, None, temp)


def _build(provider: str, model: str, api_key: str | None, temp: float) -> BaseChatModel:
    s = get_settings()  # for non-secret defaults

    if provider == "ollama":
        from langchain_ollama import ChatOllama

        return ChatOllama(model=model, temperature=temp)

    if provider == "kimi":
        # Kimi Code subscription: OpenAI-compatible endpoint, billed through
        # the membership (rate-limited, not per-token).
        import os

        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=model,
            temperature=1.0,  # Kimi coding models only accept temperature=1
            base_url=os.environ.get("KIMI_BASE_URL", "https://api.kimi.com/coding/v1"),
            api_key=api_key or os.environ["KIMI_API_KEY"],
            timeout=180,
            max_retries=3,
        )

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(model=model, temperature=temp, max_tokens=2048)

    from langchain_openai import ChatOpenAI

    return ChatOpenAI(model=model, temperature=temp,
                      api_key=api_key or None)
