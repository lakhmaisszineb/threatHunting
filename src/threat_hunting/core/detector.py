"""
Module de détection basé sur des règles simples.
Tous les seuils sont argumentés et configurables.
"""

from typing import Dict, Any, List
from collections import defaultdict
from .constants import FIELD_SRC_IP, FIELD_DST_PORT, FIELD_CONN_STATE, FAILED_CONN_STATES
from .constants import ZEEK_KEY, ZEEK_CONN
import logging


logger = logging.getLogger(__name__)


class SimpleRuleDetector:
    """
    Détecteur de comportements suspects à base de règles.

    Justification des seuils par défaut :
    - port_scan_threshold = 15 :
      Un scan de ports basique (top 10-20 ports) ou un scan horizontal léger
      génère généralement > 15 ports distincts. En dessous, on reste dans
      le bruit normal d'une machine (mises à jour, services légitimes).
    - connection_burst_threshold = 30 :
      Au-delà de ~30 connexions depuis une même IP source dans un volume
      limité, on sort du comportement utilisateur classique.
    - failed_conn_ratio = 0.6 :
      Un taux d'échec > 60% est fortement suspect (scan, brute-force, ou
      service down ciblé). Les connexions légitimes ont un taux d'échec
      beaucoup plus bas.
    - min_connections_for_ratio = 10 :
      En dessous de 10 connexions, le ratio n'est pas statistiquement fiable.
    """

    DEFAULT_CONFIG = {
        "port_scan_threshold": 15,
        "connection_burst_threshold": 30,
        "failed_conn_ratio": 0.6,
        "min_connections_for_ratio": 10,
        # time_window_seconds est réservé pour une future version
        # qui utilisera réellement les timestamps
        "time_window_seconds": 60,
    }

    def __init__(self, config: Dict[str, Any] | None = None):
        # Merge correct : la config utilisateur écrase seulement les clés fournies
        self.config = {**self.DEFAULT_CONFIG, **(config or {})}

    def detect(self, normalized_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Point d'entrée principal.

        Args:
            normalized_data: dict contenant au minimum la clé 'zeek' avec 'conn'

        Returns:
            Liste d'alertes (chaque alerte contient rule, severity, score, src_ip, description...)
        """
        alerts = []
        conn_events = normalized_data.get(ZEEK_KEY, {}).get(ZEEK_CONN, [])
        if not conn_events:
            return alerts

        alerts.extend(self._detect_port_scan(conn_events))
        alerts.extend(self._detect_connection_burst(conn_events))
        alerts.extend(self._detect_failed_connections(conn_events))
        logger.info(f"Détection terminée : {len(alerts)} alerte(s) générée(s)")
        return alerts

    def _detect_port_scan(self, conn_events: List[Dict]) -> List[Dict]:
        src_to_ports = defaultdict(set)

        for event in conn_events:
            src = event.get(FIELD_SRC_IP)
            dport = event.get(FIELD_DST_PORT)
            if src and dport is not None:
                src_to_ports[src].add(dport)

        threshold = self.config["port_scan_threshold"]
        alerts = []
        for src, ports in src_to_ports.items():
            if len(ports) >= threshold:
                score = min(0.50 + (len(ports) / 50), 0.95)
                alerts.append({
                    "rule": "possible_port_scan",
                    "severity": "medium",
                    "score": round(score, 2),
                    "src_ip": src,
                    "unique_ports": len(ports),
                    "description": f"L'IP {src} a contacté {len(ports)} ports différents (seuil={threshold}).",
                    "evidence": {"ports_sample": sorted(list(ports))[:20]}
                })
        return alerts

    def _detect_connection_burst(self, conn_events: List[Dict]) -> List[Dict]:
        """
        Version simplifiée (volume global).
        Une version future utilisera time_window_seconds + timestamps.
        """
        src_count = defaultdict(int)
        for event in conn_events:
            src = event.get(FIELD_SRC_IP)
            if src:
                src_count[src] += 1

        threshold = self.config["connection_burst_threshold"]
        alerts = []
        for src, count in src_count.items():
            if count >= threshold:
                score = min(0.30 + (count / 100), 0.80)
                alerts.append({
                    "rule": "connection_burst",
                    "severity": "low",
                    "score": round(score, 2),
                    "src_ip": src,
                    "connection_count": count,
                    "description": f"L'IP {src} a généré {count} connexions (seuil={threshold}).",
                    "evidence": {}
                })
        return alerts

    def _detect_failed_connections(self, conn_events: List[Dict]) -> List[Dict]:
        src_stats = defaultdict(lambda: {"total": 0, "failed": 0})

        for event in conn_events:
            src = event.get(FIELD_SRC_IP)
            state = event.get(FIELD_CONN_STATE, "")
            if src:
                src_stats[src]["total"] += 1
                if state in FAILED_CONN_STATES:
                    src_stats[src]["failed"] += 1

        ratio_threshold = self.config["failed_conn_ratio"]
        min_conn = self.config["min_connections_for_ratio"]
        alerts = []

        for src, stats in src_stats.items():
            if stats["total"] < min_conn:
                continue
            ratio = stats["failed"] / stats["total"]
            if ratio >= ratio_threshold:
                score = min(0.40 + ratio, 0.90)
                alerts.append({
                    "rule": "high_failed_connections",
                    "severity": "medium",
                    "score": round(score, 2),
                    "src_ip": src,
                    "failed_ratio": round(ratio, 2),
                    "total_connections": stats["total"],
                    "description": (
                        f"L'IP {src} a un taux d'échec de {ratio:.0%} "
                        f"({stats['failed']}/{stats['total']}) — seuil={ratio_threshold}."
                    ),
                    "evidence": {
                        "failed": stats["failed"],
                        "total": stats["total"]
                    }
                })
        return alerts