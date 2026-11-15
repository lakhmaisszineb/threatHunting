"""
Charge les logs Zeek (format JSON) de manière modulaire.
Facile à étendre pour ajouter d'autres logs plus tard.
"""

from pathlib import Path
from typing import Dict, List, Any
import orjson


class ZeekLoader:
    """Charge et organise les logs Zeek."""

    SUPPORTED_LOGS = ["conn", "dns", "weird"]  # on pourra en ajouter facilement

    def __init__(self, logs_dir: str | Path):
        self.logs_dir = Path(logs_dir)

    def load_log(self, log_name: str) -> List[Dict[str, Any]]:
        """Charge un log Zeek en JSON (une ligne = un événement)."""
        path = self.logs_dir / f"{log_name}.log"
        if not path.exists():
            return []

        events = []
        with open(path, "rb") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(orjson.loads(line))
        return events

    def load_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Charge tous les logs supportés."""
        return {name: self.load_log(name) for name in self.SUPPORTED_LOGS}