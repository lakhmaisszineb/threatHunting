"""
Module de recherche d'événements associés.
Permet de retrouver le contexte autour d'une alerte.
"""

from typing import Dict, Any, List


class EventCorrelator:
    """
    Recherche les événements liés à une alerte (même IP, même période, etc.).
    """

    def find_related(self, alert: Dict[str, Any], normalized_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Retourne les événements associés à une alerte.
        """
        src_ip = alert.get("src_ip")
        if not src_ip:
            return {"related_connections": [], "related_dns": [], "related_weird": []}

        zeek = normalized_data.get("zeek", {})

        related_conn = [
            e for e in zeek.get("conn", [])
            if e.get("id.orig_h") == src_ip or e.get("id.resp_h") == src_ip
        ]

        related_dns = [
            e for e in zeek.get("dns", [])
            if e.get("id.orig_h") == src_ip
        ]

        related_weird = [
            e for e in zeek.get("weird", [])
            if e.get("id.orig_h") == src_ip or e.get("id.resp_h") == src_ip
        ]

        return {
            "related_connections": related_conn[:50],   # on limite pour ne pas exploser
            "related_dns": related_dns[:20],
            "related_weird": related_weird[:20],
            "summary": {
                "total_related_conn": len(related_conn),
                "total_related_dns": len(related_dns),
                "total_related_weird": len(related_weird),
            }
        }