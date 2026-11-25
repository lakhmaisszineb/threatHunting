"""Définition du workflow LangGraph d'investigation."""

from langgraph.graph import END, StateGraph

from threat_hunting.agents.hypothesis import hypothesis_agent
from threat_hunting.agents.ioc_cti import ioc_cti_agent
from threat_hunting.agents.mitre import mitre_mapping_agent
from threat_hunting.agents.network_analysis import network_analysis_agent
from threat_hunting.agents.state import InvestigationState
from threat_hunting.agents.supervisor import supervisor_node


def build_investigation_graph():
    """Construit le workflow complet, sans appel LLM obligatoire."""
    workflow = StateGraph(InvestigationState)

    # Chaque nœud produit uniquement son résultat afin de garder l'état traçable.
    workflow.add_node("hypothesis_agent", hypothesis_agent)
    workflow.add_node("network_agent", network_analysis_agent)
    workflow.add_node("ioc_cti_agent", ioc_cti_agent)
    workflow.add_node("mitre_agent", mitre_mapping_agent)
    workflow.add_node("supervisor", supervisor_node)

    workflow.set_entry_point("hypothesis_agent")
    workflow.add_edge("hypothesis_agent", "network_agent")
    workflow.add_edge("network_agent", "ioc_cti_agent")
    workflow.add_edge("ioc_cti_agent", "mitre_agent")
    workflow.add_edge("mitre_agent", "supervisor")
    workflow.add_edge("supervisor", END)

    return workflow.compile()


def run_investigation(
    normalized_data: dict,
    alerts: list[dict],
) -> dict:
    """Exécute une investigation à partir de données normalisées et d'alertes."""
    initial_state = {
        "normalized_data": normalized_data,
        "alerts": alerts,
        "hypotheses": [],
        "ioc_findings": [],
        "mitre_mappings": [],
        "messages": [],
    }
    return build_investigation_graph().invoke(initial_state)
