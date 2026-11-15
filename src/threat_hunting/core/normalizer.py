"""
Normalise les données venant de Zeek + Scapy
vers un format unique et propre pour les agents.
"""

from typing import Dict, Any, List
from .zeek_loader import ZeekLoader
from .pcap_parser import PcapParser


class DataNormalizer:
    """Unifie Zeek logs + Scapy dans une structure standard."""

    def __init__(self, zeek_logs_dir: str, pcap_path: str | None = None):
        self.zeek_loader = ZeekLoader(zeek_logs_dir)
        self.pcap_parser = PcapParser(pcap_path) if pcap_path else None

    def normalize(self) -> Dict[str, Any]:
        """Point d'entrée principal."""
        zeek_data = self.zeek_loader.load_all()

        result = {
            "source": "zeek+scapy",
            "zeek": zeek_data,
            "scapy": None,
            "summary": self._build_summary(zeek_data),
        }

        if self.pcap_parser:
            result["scapy"] = {
                "stats": self.pcap_parser.get_basic_stats(),
                # on pourra ajouter plus tard extract_conversations() etc.
            }

        return result

    def _build_summary(self, zeek_data: Dict[str, List]) -> Dict[str, Any]:
        """Résumé rapide utile pour les agents."""
        conn = zeek_data.get("conn", [])
        return {
            "total_connections": len(conn),
            "unique_src_ips": len({c.get("id.orig_h") for c in conn if c.get("id.orig_h")}),
            "unique_dst_ips": len({c.get("id.resp_h") for c in conn if c.get("id.resp_h")}),
        }