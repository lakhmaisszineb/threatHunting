"""Extraction d'IOC et enrichissement CTI hors ligne."""

import ipaddress
from typing import Any

from threat_hunting.agents.state import InvestigationState
from threat_hunting.core.constants import FIELD_DST_IP, FIELD_SRC_IP, ZEEK_CONN, ZEEK_DNS, ZEEK_KEY


def _is_ip(value: Any) -> bool:
    """Vérifie qu'une valeur est une adresse IPv4 ou IPv6 valide."""
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _add_ioc(
    findings: dict[tuple[str, str], dict[str, Any]],
    value: Any,
    ioc_type: str,
    source: str,
    source_ip: str | None = None,
) -> None:
    """Ajoute un IOC en regroupant ses différentes références de preuve."""
    if not isinstance(value, str) or not value:
        return
    key = (ioc_type, value)
    finding = findings.setdefault(
        key,
        {
            "type": ioc_type,
            "value": value,
            "observed": True,
            "cti_status": "not_checked",
            "cti_sources": [],
            "confidence": "low",
            "evidence_references": [],
        },
    )
    if source not in finding["evidence_references"]:
        finding["evidence_references"].append(source)
    if source_ip and source_ip not in finding.setdefault("related_source_ips", []):
        finding["related_source_ips"].append(source_ip)


def ioc_cti_agent(state: InvestigationState) -> dict[str, Any]:
    """Extrait les IP observées et indique explicitement l'absence d'enrichissement distant."""
    findings: dict[tuple[str, str], dict[str, Any]] = {}
    normalized_data = state.get("normalized_data", {})
    zeek = normalized_data.get(ZEEK_KEY, {})

    for event_index, event in enumerate(zeek.get(ZEEK_CONN, [])):
        source_ip = event.get(FIELD_SRC_IP)
        for field in (FIELD_SRC_IP, FIELD_DST_IP):
            value = event.get(field)
            if _is_ip(value):
                _add_ioc(
                    findings,
                    value,
                    "ip",
                    f"zeek.conn[{event_index}].{field}",
                    source_ip=source_ip,
                )

    for event_index, event in enumerate(zeek.get(ZEEK_DNS, [])):
        source_ip = event.get(FIELD_SRC_IP)
        for field in ("query", "answers"):
            value = event.get(field)
            values = value if isinstance(value, list) else [value]
            for item in values:
                if isinstance(item, str) and not _is_ip(item):
                    _add_ioc(
                        findings,
                        item,
                        "domain",
                        f"zeek.dns[{event_index}].{field}",
                        source_ip=source_ip,
                    )

    ioc_findings = list(findings.values())
    return {
        "ioc_findings": ioc_findings,
        "current_step": "ioc_cti_completed",
        "messages": [
            f"[ioc_cti_agent] {len(ioc_findings)} IOC(s) extrait(s); CTI distant non configuré"
        ],
    }
