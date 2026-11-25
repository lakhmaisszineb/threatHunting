"""Mapping local et prudent vers MITRE ATT&CK."""

from typing import Any

from threat_hunting.agents.state import InvestigationState


RULE_TO_TECHNIQUE = {
    "possible_port_scan": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "justification": (
            "La règle a observé une même source contacter plusieurs ports. "
            "Cela est compatible avec une reconnaissance active, sans la prouver."
        ),
    },
}


def mitre_mapping_agent(state: InvestigationState) -> dict[str, Any]:
    """Associe uniquement les comportements disposant d'une justification suffisante."""
    mappings: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()

    for alert in state.get("alerts", []):
        rule = alert.get("rule")
        template = RULE_TO_TECHNIQUE.get(rule)
        if not template:
            continue

        key = (template["technique_id"], alert.get("src_ip"))
        if key in seen:
            continue
        seen.add(key)
        mappings.append(
            {
                **template,
                "source_rule": rule,
                "source_ip": alert.get("src_ip"),
                "evidence_status": "supported_behavior_not_confirmed_attack",
                "confidence": "low",
            }
        )

    return {
        "mitre_mappings": mappings,
        "current_step": "mitre_mapping_completed",
        "messages": [f"[mitre_agent] {len(mappings)} mapping(s) produite(s)"],
    }
