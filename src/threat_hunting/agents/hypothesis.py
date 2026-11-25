"""Génération déterministe d'hypothèses d'investigation."""

from typing import Any

from threat_hunting.agents.state import InvestigationState


RULE_HYPOTHESES = {
    "possible_port_scan": {
        "title": "L'adresse source pourrait effectuer une reconnaissance de ports",
        "description": (
            "Une même adresse source a contacté plusieurs ports distincts. "
            "Ce comportement peut correspondre à une reconnaissance, mais il "
            "peut aussi être causé par un outil d'administration ou un test autorisé."
        ),
        "evidence_to_collect": [
            "Les ports et adresses de destination contactés",
            "La période pendant laquelle les connexions ont eu lieu",
            "Le statut des connexions et les journaux de l'hôte source",
        ],
    },
    "connection_burst": {
        "title": "L'adresse source pourrait générer un volume inhabituel de connexions",
        "description": (
            "Un volume élevé de connexions a été observé pour une même adresse source. "
            "Il faut vérifier la fenêtre temporelle et le rôle de l'hôte avant de conclure."
        ),
        "evidence_to_collect": [
            "Les timestamps de toutes les connexions",
            "Les destinations et ports concernés",
            "Le rôle connu de l'hôte source",
        ],
    },
    "high_failed_connections": {
        "title": "L'adresse source pourrait sonder des services indisponibles",
        "description": (
            "Une proportion élevée de connexions a échoué. Cela peut indiquer un scan, "
            "mais aussi un service arrêté, un pare-feu ou une mauvaise configuration."
        ),
        "evidence_to_collect": [
            "Les états Zeek des connexions",
            "Les services et ports ciblés",
            "Les changements de configuration ou incidents connus",
        ],
    },
}


def hypothesis_agent(state: InvestigationState) -> dict[str, Any]:
    """Transforme les alertes en hypothèses vérifiables et traçables."""
    hypotheses: list[dict[str, Any]] = []

    for index, alert in enumerate(state.get("alerts", []), start=1):
        rule = alert.get("rule", "unknown_rule")
        template = RULE_HYPOTHESES.get(
            rule,
            {
                "title": "Un comportement réseau nécessite une vérification",
                "description": "L'alerte doit être confrontée aux événements réseau disponibles.",
                "evidence_to_collect": ["Les événements à l'origine de l'alerte"],
            },
        )
        hypotheses.append(
            {
                "id": f"H-{index:03d}",
                "status": "open",
                "rule": rule,
                "title": template["title"],
                "description": template["description"],
                "source_ip": alert.get("src_ip"),
                "evidence_to_collect": template["evidence_to_collect"],
                "alert_reference": {
                    "rule": rule,
                    "source_ip": alert.get("src_ip"),
                    "description": alert.get("description"),
                },
            }
        )

    return {
        "hypotheses": hypotheses,
        "current_step": "hypotheses_completed",
        "messages": [f"[hypothesis_agent] {len(hypotheses)} hypothèse(s) générée(s)"],
    }
