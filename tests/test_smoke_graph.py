"""Milestone 1 smoke test: proves config, whitelist guard and LangGraph plumbing
work end-to-end WITHOUT any API key (uses a deterministic fake model).
"""

from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph

from aegis.config import get_settings
from aegis.graph.state import AegisState


def test_whitelist_guard():
    s = get_settings()
    assert s.is_target_allowed("http://localhost:8100/chat")
    assert not s.is_target_allowed("https://evil.example.com")


def test_minimal_graph_flow():
    def recon_node(state: AegisState):
        return {
            "status": "recon",
            "messages": [AIMessage(content="recon done")],
            "planned_techniques": [],
        }

    def done_node(state: AegisState):
        return {"status": "done"}

    g = StateGraph(AegisState)
    g.add_node("recon", recon_node)
    g.add_node("finish", done_node)
    g.add_edge(START, "recon")
    g.add_edge("recon", "finish")
    g.add_edge("finish", END)
    app = g.compile()

    out = app.invoke(
        {
            "messages": [],
            "target_url": "http://localhost:8100",
            "profile": None,
            "planned_techniques": [],
            "attempts": [],
            "findings": [],
            "requests_used": 0,
            "status": "init",
        }
    )
    assert out["status"] == "done"
