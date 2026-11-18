"""
Générateur de rapport initial (semaine 2).
Produit un rapport structuré + version texte lisible.
"""

from typing import Dict, Any, List
from datetime import datetime, timezone
import orjson
from pathlib import Path


class ReportGenerator:
    """Génère un rapport d'investigation initial."""

    def generate(
        self,
        normalized_data: Dict[str, Any],
        alerts: List[Dict[str, Any]],
        correlations: List[Dict[str, Any]] | None = None
    ) -> Dict[str, Any]:
        """Construit le rapport complet."""

        report = {
            "meta": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "version": "0.1.0-week2",
                "type": "initial_investigation_report"
            },
            "summary": normalized_data.get("summary", {}),
            "alerts": alerts,
            "alert_count": len(alerts),
            "highest_severity": self._get_highest_severity(alerts),
            "correlations": correlations or [],
            "raw_stats": {
                "zeek_logs_loaded": list(normalized_data.get("zeek", {}).keys()),
                "scapy_available": normalized_data.get("scapy") is not None
            }
        }
        return report

    def to_json(self, report: Dict[str, Any], path: str | Path) -> None:
        """Sauvegarde le rapport en JSON."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(orjson.dumps(report, option=orjson.OPT_INDENT_2))

    def to_text(self, report: Dict[str, Any]) -> str:
        """Version texte lisible pour affichage / soutenance."""
        lines = []
        lines.append("=" * 60)
        lines.append("RAPPORT D'INVESTIGATION INITIAL - Threat Hunting")
        lines.append("=" * 60)
        lines.append(f"Généré le : {report['meta']['generated_at']}")
        lines.append(f"Nombre d'alertes : {report['alert_count']}")
        lines.append(f"Sévérité max   : {report['highest_severity']}")
        lines.append("")
        lines.append("--- Résumé ---")
        for k, v in report.get("summary", {}).items():
            lines.append(f"  {k}: {v}")
        lines.append("")
        lines.append("--- Alertes détectées ---")

        if not report["alerts"]:
            lines.append("  Aucune alerte.")
        else:
            for i, alert in enumerate(report["alerts"], 1):
                lines.append(f"\n[{i}] {alert.get('rule')} | sévérité: {alert.get('severity')} | score: {alert.get('score', 0):.2f}")
                lines.append(f"    {alert.get('description')}")
                if "src_ip" in alert:
                    lines.append(f"    Source IP: {alert['src_ip']}")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

    def _get_highest_severity(self, alerts: List[Dict]) -> str:
        order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        if not alerts:
            return "none"
        return max(alerts, key=lambda a: order.get(a.get("severity", "low"), 0)).get("severity", "low")