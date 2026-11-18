"""
Définition du graphe LangGraph.
"""

from langgraph.graph import StateGraph, END
from threat_hunting.agents.state import InvestigationState
from threat_hunting.agents.supervisor import supervisor_node


def build_investigation_graph():
    """
    Construit le graphe d'investigation.
    Pour l'instant : uniquement le Superviseur (on ajoutera les autres agents ensuite).
    """
    workflow = StateGraph(InvestigationState)

    # Ajout des nœuds
    workflow.add_node("supervisor", supervisor_node)

    # Point d'entrée
    workflow.set_entry_point("supervisor")

    # Pour l'instant le superviseur termine directement
    workflow.add_edge("supervisor", END)

    return workflow.compile()