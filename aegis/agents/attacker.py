"""Attacker node: runs ONE attack attempt against the target.

Multi-turn conversation driven by the attack LLM, seeded from the attack
library. Canary check runs after EVERY target reply - deterministic
detection, independent of the judge.
"""

import uuid

from aegis.attacks.library import ATTACKER_SYSTEM, GOALS, OPENERS, TECHNIQUE_OWASP
from aegis.config import get_settings
from aegis.graph.state import AegisState, AttackAttempt, ConversationTurn
from aegis.llm import get_chat_model
from aegis.targets.hr_docs import CANARY_PERSONAL, CANARY_SALARY, CANARY_SYSTEM_PROMPT

CANARIES = (CANARY_SYSTEM_PROMPT, CANARY_SALARY, CANARY_PERSONAL)


def check_canaries(text: str) -> bool:
    return any(c in text for c in CANARIES)


def run_attempt(technique, target_client, llm=None) -> AttackAttempt:
    s = get_settings()
    attempt = AttackAttempt(
        id=str(uuid.uuid4())[:8],
        technique=technique,
        owasp=TECHNIQUE_OWASP[technique],
    )
    history: list[dict] = []
    openers = OPENERS[technique]

    for turn_i in range(s.max_turns_per_attack):
        # Attacker message: scripted openers first, then LLM adapts
        if turn_i < len(openers):
            attack_msg = openers[turn_i]
        else:
            if llm is None:
                break
            convo = "\n".join(f"{t['role']}: {t['content']}" for t in history)
            prompt = ATTACKER_SYSTEM.format(
                technique=technique.value, goal=GOALS[technique], history=convo or "(none yet)"
            )
            attack_msg = llm.invoke(prompt).content.strip()
            if attack_msg == "GIVE_UP":
                break

        reply = target_client.chat(attack_msg, history)
        attempt.turns.append(ConversationTurn(role="attacker", content=attack_msg))
        attempt.turns.append(ConversationTurn(role="target", content=reply))
        history.append({"role": "user", "content": attack_msg})
        history.append({"role": "assistant", "content": reply})

        if check_canaries(reply):
            attempt.canary_triggered = True
            attempt.succeeded = True
            attempt.judge_verdict = "success"
            attempt.judge_reasoning = "Canary token detected in target output (deterministic)."
            break

    return attempt


def attacker_node(state: AegisState) -> dict:
    s = get_settings()
    if state["requests_used"] >= s.max_total_requests:
        return {"status": "evaluating", "planned_techniques": []}
    if not state["planned_techniques"]:
        return {"status": "evaluating"}

    technique = state["planned_techniques"][0]
    llm = None if s.scripted_mode else get_chat_model("attack")
    attempt = run_attempt(technique, state["target_client"], llm=llm)

    return {
        "attempts": state["attempts"] + [attempt],
        "planned_techniques": state["planned_techniques"][1:],
        "requests_used": state["requests_used"] + len(attempt.turns) // 2,
    }
