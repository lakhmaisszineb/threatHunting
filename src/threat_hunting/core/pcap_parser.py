"""
Analyse complémentaire avec Scapy.
Sert surtout pour deep inspection et extraction de features personnalisées.
"""

from pathlib import Path
from typing import List, Dict, Any
from scapy.all import rdpcap, IP, TCP, UDP, DNS


class PcapParser:
    """Parser Scapy pour analyse fine."""

    def __init__(self, pcap_path: str | Path):
        self.pcap_path = Path(pcap_path)
        self.packets = None

    def load(self):
        """Charge le PCAP en mémoire."""
        self.packets = rdpcap(str(self.pcap_path))
        return self

    def get_basic_stats(self) -> Dict[str, Any]:
        """Statistiques de base (complément de Zeek)."""
        if self.packets is None:
            self.load()

        total = len(self.packets)
        ip_packets = [p for p in self.packets if IP in p]
        tcp_packets = [p for p in self.packets if TCP in p]
        udp_packets = [p for p in self.packets if UDP in p]

        return {
            "total_packets": total,
            "ip_packets": len(ip_packets),
            "tcp_packets": len(tcp_packets),
            "udp_packets": len(udp_packets),
        }

    def extract_conversations(self) -> List[Dict[str, Any]]:
        """Exemple d'extraction personnalisée (à enrichir plus tard)."""
        if self.packets is None:
            self.load()

        conversations = []
        for pkt in self.packets:
            if IP in pkt:
                conv = {
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "proto": pkt[IP].proto,
                }
                if TCP in pkt:
                    conv.update({"sport": pkt[TCP].sport, "dport": pkt[TCP].dport, "flags": str(pkt[TCP].flags)})
                elif UDP in pkt:
                    conv.update({"sport": pkt[UDP].sport, "dport": pkt[UDP].dport})
                conversations.append(conv)
        return conversations