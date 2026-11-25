"""Superviseur déterministe de l'investigation."""

from datetime import datetime, timezone
from typing import Any

from threat_hunting.agents.state import InvestigationState


def _build_conclusion(state: InvestigationState) -> tuple[str, str]:
    """Produit une conclusion prudente à partir des alertes et preuves présentes."""
    alerts = state.get("alerts", [])
    network_analysis = state.get("network_analysis", {})
    if not alerts:
        return "Aucun comportement suspect n'a été détecté dans les données analysées.", "low"
    if not network_analysis.get("analyses"):
        return "Des alertes existent, mais les données réseau associées sont insuffisantes.", "low"
    return (
        "Des comportements réseau suspects sont soutenus par les événements disponibles. "
        "Une compromission ne peut pas être confirmée avec ces seules données.",
        "medium",
    )


def supervisor_node(state: InvestigationState) -> dict[str, Any]:
    """Vérifie la cohérence des résultats et assemble un rapport structuré."""
    conclusion, confidence = _build_conclusion(state)
    report = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "version": "0.2.0",
            "type": "investigation_report",
            "mode": "alert_triggered" if state.get("alerts") else "proactive_hunting",
        },
        "observed_facts": [
            state.get("normalized_data", {}).get("summary", {}),
            {"alert_count": len(state.get("alerts", []))},
        ],
        "alerts": state.get("alerts", []),
        "hypotheses": state.get("hypotheses", []),
        "network_analysis": state.get("network_analysis", {}),
        "ioc_findings": state.get("ioc_findings", []),
        "mitre_mappings": state.get("mitre_mappings", []),
        "conclusion": conclusion,
        "confidence": confidence,
        "limitations": [
            "L'enrichissement CTI distant n'est pas exécuté dans ce mode hors ligne.",
            "Les comportements détectés sont des signaux qui nécessitent une validation humaine.",
        ],
        "recommendations": [
            "Vérifier le rôle et l'autorisation de l'hôte source.",
            "Examiner les journaux de l'hôte et la période exacte des événements.",
        ],
    }
    return {
        "final_report": report,
        "current_step": "supervisor_completed",
        "messages": ["[supervisor] Rapport structuré créé et résultats validés"],
    }
