"""
Pipeline principal d'ingestion.
Point d'entrée unique et stable pour le reste du système.
"""

from pathlib import Path
from typing import Dict, Any
from .normalizer import DataNormalizer


class IngestionPipeline:
    """
    Pipeline modulaire.
    Aujourd'hui : logs Zeek pré-générés + Scapy optionnel.
    Plus tard : on pourra ajouter le lancement dynamique de Zeek ici sans casser le reste.
    """

    def __init__(self, zeek_logs_dir: str, pcap_path: str | None = None):
        self.normalizer = DataNormalizer(zeek_logs_dir, pcap_path)

    def run(self) -> Dict[str, Any]:
        """Exécute le pipeline et retourne les données normalisées."""
        return self.normalizer.normalize()