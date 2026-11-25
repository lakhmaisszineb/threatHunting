"""Analyse réseau déterministe basée sur les événements normalisés."""

from collections import Counter
from typing import Any

from threat_hunting.agents.state import InvestigationState
from threat_hunting.core.constants import (
    FIELD_CONN_STATE,
    FIELD_DST_IP,
    FIELD_DST_PORT,
    FIELD_SRC_IP,
    ZEEK_CONN,
    ZEEK_DNS,
    ZEEK_KEY,
    ZEEK_WEIRD,
)


def _events_for_source(events: list[dict[str, Any]], source_ip: str | None) -> list[dict[str, Any]]:
    """Retourne uniquement les événements associés à l'adresse source."""
    if not source_ip:
        return []
    return [event for event in events if event.get(FIELD_SRC_IP) == source_ip]


def _analyze_alert(alert: dict[str, Any], zeek: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Construit une analyse courte et fondée sur les événements disponibles."""
    source_ip = alert.get("src_ip")
    connections = _events_for_source(zeek.get(ZEEK_CONN, []), source_ip)
    dns_events = _events_for_source(zeek.get(ZEEK_DNS, []), source_ip)
    weird_events = _events_for_source(zeek.get(ZEEK_WEIRD, []), source_ip)

    destination_ips = sorted({event.get(FIELD_DST_IP) for event in connections if event.get(FIELD_DST_IP)})
    destination_ports = sorted({event.get(FIELD_DST_PORT) for event in connections if event.get(FIELD_DST_PORT) is not None})
    states = Counter(event.get(FIELD_CONN_STATE, "unknown") for event in connections)

    evidence = {
        "alert_rule": alert.get("rule"),
        "source_ip": source_ip,
        "connection_count": len(connections),
        "dns_event_count": len(dns_events),
        "weird_event_count": len(weird_events),
        "unique_destination_ips": destination_ips,
        "unique_destination_ports": destination_ports,
        "connection_states": dict(states),
    }

    # La conclusion reste descriptive : elle ne transforme pas une alerte en compromission confirmée.
    if not connections:
        conclusion = "Aucun événement de connexion correspondant n'a été trouvé dans les données chargées."
        confidence = "low"
    else:
        conclusion = "Les événements disponibles soutiennent le comportement détecté, sans confirmer une compromission."
        confidence = "medium"

    return {
        "alert_rule": alert.get("rule"),
        "source_ip": source_ip,
        "conclusion": conclusion,
        "confidence": confidence,
        "evidence": evidence,
    }


def network_analysis_agent(state: InvestigationState) -> dict[str, Any]:
    """Analyse les connexions, DNS et événements atypiques liés aux alertes."""
    normalized_data = state.get("normalized_data", {})
    zeek = normalized_data.get(ZEEK_KEY, {})
    analyses = [_analyze_alert(alert, zeek) for alert in state.get("alerts", [])]

    return {
        "network_analysis": {
            "analyses": analyses,
            "total_analyzed_alerts": len(analyses),
            "source": "normalized_zeek_events",
        },
        "current_step": "network_analysis_completed",
        "messages": [f"[network_agent] {len(analyses)} alerte(s) analysée(s)"],
    }
