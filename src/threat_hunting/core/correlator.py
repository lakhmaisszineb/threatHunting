"""
Module de recherche d'événements associés.
"""

from typing import Dict, Any, List
from .constants import FIELD_SRC_IP, FIELD_DST_IP, ZEEK_CONN, ZEEK_DNS, ZEEK_WEIRD


class EventCorrelator:
    """Recherche les événements liés à une alerte."""

    MAX_RELATED_CONN = 50
    MAX_RELATED_DNS = 20
    MAX_RELATED_WEIRD = 20

    def _filter_by_ip(
        self,
        events: List[Dict],
        src_ip: str,
        check_src: bool = True,
        check_dst: bool = False
    ) -> List[Dict]:
        """Helper unique pour éviter la duplication."""
        result = []
        for e in events:
            match = False
            if check_src and e.get(FIELD_SRC_IP) == src_ip:
                match = True
            if check_dst and e.get(FIELD_DST_IP) == src_ip:
                match = True
            if match:
                result.append(e)
        return result

    def find_related(self, alert: Dict[str, Any], normalized_data: Dict[str, Any]) -> Dict[str, Any]:
        src_ip = alert.get("src_ip")
        if not src_ip:
            return {
                "related_connections": [],
                "related_dns": [],
                "related_weird": [],
                "summary": {"total_related_conn": 0, "total_related_dns": 0, "total_related_weird": 0}
            }

        zeek = normalized_data.get("zeek", {})

        related_conn = self._filter_by_ip(zeek.get(ZEEK_CONN, []), src_ip, True, True)[:self.MAX_RELATED_CONN]
        related_dns = self._filter_by_ip(zeek.get(ZEEK_DNS, []), src_ip, True, False)[:self.MAX_RELATED_DNS]
        related_weird = self._filter_by_ip(zeek.get(ZEEK_WEIRD, []), src_ip, True, True)[:self.MAX_RELATED_WEIRD]

        return {
            "related_connections": related_conn,
            "related_dns": related_dns,
            "related_weird": related_weird,
            "summary": {
                "total_related_conn": len(related_conn),
                "total_related_dns": len(related_dns),
                "total_related_weird": len(related_weird),
            }
        }