"""Shared state schema for the Aegis attack graph.

This is the contract between every node: recon, attack agents, evaluator
and report writer all read/write this single typed state.
"""

from enum import Enum
from typing import Annotated, Literal

from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field
from typing_extensions import TypedDict


class OwaspCategory(str, Enum):
    """Finding categories: OWASP LLM Top 10 (2025) + classic web/WS surface."""

    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_SENSITIVE_DISCLOSURE = "LLM02"
    LLM06_EXCESSIVE_AGENCY = "LLM06"
    LLM07_SYSTEM_PROMPT_LEAK = "LLM07"
    LLM08_VECTOR_WEAKNESS = "LLM08"  # RAG / embedding poisoning & leakage
    # Classic web surface (deterministic checks, no LLM needed)
    WEB_HEADERS = "WEB-HEADERS"
    WEB_CORS = "WEB-CORS"
    WEB_EXPOSED = "WEB-EXPOSED"
    WEB_COOKIES = "WEB-COOKIES"
    WEB_JWT = "WEB-JWT"
    WS_AUTH = "WS-AUTH"
    WS_INJECTION = "WS-INJECTION"
    WS_RATELIMIT = "WS-RATELIMIT"


class AttackTechnique(str, Enum):
    DIRECT_INJECTION = "direct_injection"
    JAILBREAK_ROLEPLAY = "jailbreak_roleplay"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    RAG_CONTEXT_EXFIL = "rag_context_exfil"
    TOOL_ABUSE = "tool_abuse"
    MULTI_TURN_ESCALATION = "multi_turn_escalation"
    INDIRECT_RAG_INJECTION = "indirect_rag_injection"
    MARKDOWN_EXFIL = "markdown_exfil"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConversationTurn(BaseModel):
    role: Literal["attacker", "target"]
    content: str


class AttackAttempt(BaseModel):
    """One full attack run: a technique applied over N turns against the target."""

    id: str
    technique: AttackTechnique
    owasp: OwaspCategory
    turns: list[ConversationTurn] = Field(default_factory=list)
    # Judge output
    succeeded: bool | None = None
    judge_verdict: Literal["success", "partial", "failure", "pending"] = "pending"
    judge_reasoning: str = ""
    canary_triggered: bool = False  # deterministic detection, no LLM needed


class Finding(BaseModel):
    """A confirmed vulnerability, ready for the report."""

    title: str
    owasp: OwaspCategory
    severity: Severity
    evidence: list[ConversationTurn]
    impact: str
    remediation: str
    attempt_id: str


class TargetProfile(BaseModel):
    """What the recon agent learned about the target."""

    url: str
    has_rag: bool | None = None
    has_tools: bool | None = None
    suspected_guardrails: list[str] = Field(default_factory=list)
    notes: str = ""


class AegisState(TypedDict, total=False):
    messages: Annotated[list, add_messages]  # internal orchestration chatter
    target_url: str
    owner: str | None  # scan owner - unlocks user-verified targets
    target_client: object  # runtime-only TargetClient (set by scope guard)
    profile: TargetProfile | None
    planned_techniques: list[AttackTechnique]
    attempts: list[AttackAttempt]
    findings: list[Finding]
    requests_used: int  # budget guardrail bookkeeping
    status: Literal["init", "recon", "attacking", "evaluating", "reporting", "done", "refused"]
    report_path: str
