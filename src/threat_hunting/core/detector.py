"""
Module de détection basé sur des règles simples.
Facile à étendre plus tard (règles plus avancées ou agents).
"""

from typing import Dict, Any, List
from collections import defaultdict
from datetime import datetime, timedelta


class SimpleRuleDetector:
    """
    Détecteur de comportements suspects à base de règles.
    Chaque règle retourne une alerte avec un score de risque.
    """

    def __init__(self, config: Dict[str, Any] | None = None):
        # Seuils par défaut (facilement modifiables)
        self.config = config or {
            "port_scan_threshold": 15,          # nb de ports différents contactés
            "connection_burst_threshold": 30,   # nb de connexions en peu de temps
            "time_window_seconds": 60,
            "failed_conn_ratio": 0.6,           # proportion de connexions échouées
        }

    def detect(self, normalized_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Point d'entrée principal. Retourne une liste d'alertes."""
        alerts = []

        conn_events = normalized_data.get("zeek", {}).get("conn", [])
        if not conn_events:
            return alerts

        # Règle 1 : Possible Port Scan
        alerts.extend(self._detect_port_scan(conn_events))

        # Règle 2 : Burst de connexions
        alerts.extend(self._detect_connection_burst(conn_events))

        # Règle 3 : Beaucoup de connexions échouées
        alerts.extend(self._detect_failed_connections(conn_events))

        return alerts

    def _detect_port_scan(self, conn_events: List[Dict]) -> List[Dict]:
        """Détecte si une IP source contacte beaucoup de ports différents."""
        alerts = []
        src_to_ports = defaultdict(set)

        for event in conn_events:
            src = event.get("id.orig_h")
            dport = event.get("id.resp_p")
            if src and dport is not None:
                src_to_ports[src].add(dport)

        threshold = self.config["port_scan_threshold"]
        for src, ports in src_to_ports.items():
            if len(ports) >= threshold:
                alerts.append({
                    "rule": "possible_port_scan",
                    "severity": "medium",
                    "score": min(0.5 + (len(ports) / 50), 0.95),
                    "src_ip": src,
                    "unique_ports": len(ports),
                    "description": f"L'IP {src} a contacté {len(ports)} ports différents.",
                    "evidence": {
                        "ports_sample": list(ports)[:20]
                    }
                })
        return alerts

    def _detect_connection_burst(self, conn_events: List[Dict]) -> List[Dict]:
        """Détecte un grand nombre de connexions en peu de temps."""
        # Version simplifiée : on compte juste le volume global par source
        # (une version plus précise avec timestamps viendra plus tard)
        alerts = []
        src_count = defaultdict(int)

        for event in conn_events:
            src = event.get("id.orig_h")
            if src:
                src_count[src] += 1

        threshold = self.config["connection_burst_threshold"]
        for src, count in src_count.items():
            if count >= threshold:
                alerts.append({
                    "rule": "connection_burst",
                    "severity": "low",
                    "score": min(0.3 + (count / 100), 0.8),
                    "src_ip": src,
                    "connection_count": count,
                    "description": f"L'IP {src} a généré {count} connexions.",
                    "evidence": {}
                })
        return alerts

    def _detect_failed_connections(self, conn_events: List[Dict]) -> List[Dict]:
        """Détecte un taux élevé de connexions échouées (S0, REJ, etc.)."""
        alerts = []
        src_stats = defaultdict(lambda: {"total": 0, "failed": 0})

        failed_states = {"S0", "REJ", "RSTO", "RSTOS0", "RSTR", "OTH"}

        for event in conn_events:
            src = event.get("id.orig_h")
            state = event.get("conn_state", "")
            if src:
                src_stats[src]["total"] += 1
                if state in failed_states:
                    src_stats[src]["failed"] += 1

        ratio_threshold = self.config["failed_conn_ratio"]
        for src, stats in src_stats.items():
            if stats["total"] < 10:
                continue
            ratio = stats["failed"] / stats["total"]
            if ratio >= ratio_threshold:
                alerts.append({
                    "rule": "high_failed_connections",
                    "severity": "medium",
                    "score": min(0.4 + ratio, 0.9),
                    "src_ip": src,
                    "failed_ratio": round(ratio, 2),
                    "total_connections": stats["total"],
                    "description": f"L'IP {src} a un taux d'échec de {ratio:.0%}.",
                    "evidence": {
                        "failed": stats["failed"],
                        "total": stats["total"]
                    }
                })
        return alerts