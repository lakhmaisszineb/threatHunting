"""
État partagé entre tous les agents (LangGraph).
"""

from typing import TypedDict, List, Dict, Any, Optional, Annotated
import operator


class InvestigationState(TypedDict):
    """
    État global de l'investigation.
    Tous les agents lisent et écrivent dans cet état.
    """

    # Données d'entrée
    normalized_data: Dict[str, Any]
    alerts: List[Dict[str, Any]]

    # Travaux des agents
    hypotheses: Annotated[List[Dict[str, Any]], operator.add]
    network_analysis: Optional[Dict[str, Any]]
    ioc_findings: Annotated[List[Dict[str, Any]], operator.add]
    mitre_mappings: Annotated[List[Dict[str, Any]], operator.add]

    # Contrôle
    current_step: str
    messages: Annotated[List[str], operator.add]

    # Rapport final
    final_report: Optional[Dict[str, Any]]


