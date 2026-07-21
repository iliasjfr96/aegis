"""The Aegis attack graph: scope guard -> recon -> plan -> attack -> (loop)
-> evaluate -> report. Adaptive: the planner re-runs between attacks.
"""

from langgraph.graph import END, START, StateGraph

from aegis.agents.attacker import attacker_node
from aegis.agents.evaluator import evaluator_node
from aegis.agents.planner import planner_node
from aegis.agents.recon import recon_node
from aegis.graph.state import AegisState
from aegis.observability import traced
from aegis.targets.client import TargetClient, TargetRefusedError


def scope_guard_node(state: AegisState) -> dict:
    from aegis.auth.scope import is_allowed

    if not is_allowed(state["target_url"], state.get("owner")):
        return {"status": "refused"}
    return {"status": "recon",
            "target_client": TargetClient(state["target_url"], owner=state.get("owner"))}


def report_node(state: AegisState) -> dict:
    from aegis.report.generator import generate_report

    path = generate_report(
        target_url=state["target_url"],
        profile=state.get("profile"),
        findings=state["findings"],
        attempts_count=len(state["attempts"]),
        requests_used=state["requests_used"],
    )
    return {"status": "done", "report_path": str(path)}


def _route_after_guard(state: AegisState) -> str:
    return "recon" if state["status"] == "recon" else END


def _route_after_attack(state: AegisState) -> str:
    if state["status"] == "evaluating" or not state["planned_techniques"]:
        return "evaluate"
    return "attack"


def build_graph():
    g = StateGraph(AegisState)
    g.add_node("scope_guard", traced("scope_guard")(scope_guard_node))
    g.add_node("recon", traced("recon")(recon_node))
    g.add_node("plan", traced("plan")(planner_node))
    g.add_node("attack", traced("attack")(attacker_node))
    g.add_node("evaluate", traced("evaluate")(evaluator_node))
    g.add_node("report", traced("report")(report_node))

    g.add_edge(START, "scope_guard")
    g.add_conditional_edges("scope_guard", _route_after_guard, {"recon": "recon", END: END})
    g.add_edge("recon", "plan")
    g.add_edge("plan", "attack")
    g.add_conditional_edges("attack", _route_after_attack, {"attack": "plan", "evaluate": "evaluate"})
    g.add_edge("evaluate", "report")
    g.add_edge("report", END)
    return g.compile()
