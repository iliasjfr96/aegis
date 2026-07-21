"""Kimi provider: builds an OpenAI-compatible client pointed at the Kimi
Code subscription endpoint - no network call made in tests."""

import os

import aegis.llm.factory as factory
from aegis.config import get_settings


def test_kimi_provider_uses_subscription_endpoint(monkeypatch):
    monkeypatch.setenv("KIMI_API_KEY", "sk-test-kimi")
    s = get_settings()
    monkeypatch.setattr(s, "llm_provider", "kimi")
    monkeypatch.setattr(s, "attack_model", "kimi-for-coding")

    llm = factory.get_chat_model("attack")
    assert "api.kimi.com/coding" in str(llm.openai_api_base)
    assert llm.model_name == "kimi-for-coding"


def test_kimi_judge_role_uses_judge_model(monkeypatch):
    monkeypatch.setenv("KIMI_API_KEY", "sk-test-kimi")
    s = get_settings()
    monkeypatch.setattr(s, "llm_provider", "kimi")
    monkeypatch.setattr(s, "judge_model", "k3")

    llm = factory.get_chat_model("judge")
    assert llm.model_name == "k3"
    assert llm.temperature == 1.0  # Kimi coding endpoint requires temperature=1
