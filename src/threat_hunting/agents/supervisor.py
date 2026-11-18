"""
Agent Superviseur.
Il orchestre les autres agents et produit le rapport final.
"""

from typing import Dict, Any
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

from threat_hunting.config import (
    GROQ_API_KEY,
    LLM_MODEL,
    LLM_TEMPERATURE,
    AGENT_SUPERVISOR
)
from threat_hunting.agents.state import InvestigationState


def get_llm():
    """Retourne le LLM configuré (centralisé)."""
    return ChatGroq(
        api_key=GROQ_API_KEY,
        model=LLM_MODEL,
        temperature=LLM_TEMPERATURE
    )


def supervisor_node(state: InvestigationState) -> Dict[str, Any]:
    """
    Nœud Superviseur.
    Analyse l'état actuel et décide de la suite + prépare le rapport final.
    """
    llm = get_llm()

    # Résumé de ce qui a déjà été fait
    summary = {
        "nb_alerts": len(state.get("alerts", [])),
        "nb_hypotheses": len(state.get("hypotheses", [])),
        "has_network_analysis": state.get("network_analysis") is not None,
        "nb_ioc": len(state.get("ioc_findings", [])),
        "nb_mitre": len(state.get("mitre_mappings", [])),
    }

    system_prompt = f"""Tu es le Superviseur d'un système multi-agents de Threat Hunting.
Ton rôle est de coordonner l'investigation et de produire un rapport final cohérent et justifié par des preuves.

État actuel de l'investigation :
{summary}

Règles strictes :
- Ne jamais inventer de preuves.
- Toute conclusion doit être appuyée par les données disponibles.
- Si les informations sont insuffisantes, le dire clairement.
"""

    human_prompt = """En te basant sur l'état actuel, produis un résumé clair de l'investigation et indique si on peut clôturer le rapport ou s'il manque des éléments importants."""

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=human_prompt)
    ]

    response = llm.invoke(messages)

    return {
        "messages": [f"[{AGENT_SUPERVISOR}] {response.content}"],
        "current_step": "supervisor_completed"
    }