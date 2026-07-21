"""Planner node: adaptively chooses which attack techniques to run,
based on what recon learned. This is the 'agentic' brain of Aegis.
"""

from aegis.graph.state import AegisState, AttackTechnique


def planner_node(state: AegisState) -> dict:
    profile = state["profile"]
    already = {a.technique for a in state["attempts"]}
    plan: list[AttackTechnique] = []

    # Everyone gets the basics
    plan.append(AttackTechnique.SYSTEM_PROMPT_EXTRACTION)
    plan.append(AttackTechnique.DIRECT_INJECTION)

    # Adaptive branching from the recon profile
    if profile and profile.has_rag:
        plan.append(AttackTechnique.RAG_CONTEXT_EXFIL)
        plan.append(AttackTechnique.INDIRECT_RAG_INJECTION)
    if profile and profile.has_tools:
        plan.append(AttackTechnique.TOOL_ABUSE)
    if profile and "input_filter" in profile.suspected_guardrails:
        # Naive blocklist detected -> bypass with roleplay & multi-turn
        plan.append(AttackTechnique.JAILBREAK_ROLEPLAY)
        plan.append(AttackTechnique.MULTI_TURN_ESCALATION)

    # After partial failures, retry blocked techniques with a different angle
    for attempt in state["attempts"]:
        if attempt.judge_verdict == "partial" and attempt.technique not in plan:
            plan.append(AttackTechnique.MULTI_TURN_ESCALATION)

    # Late-game: exfiltration via rendered channels once basic exfil worked
    if any(a.succeeded for a in state["attempts"]):
        plan.append(AttackTechnique.MARKDOWN_EXFIL)

    plan = [t for t in plan if t not in already]
    return {"planned_techniques": plan, "status": "attacking"}
