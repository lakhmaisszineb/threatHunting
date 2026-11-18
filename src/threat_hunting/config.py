"""
Configuration centralisée du projet.
Tout ce qui peut changer (clés, modèles, noms, seuils...) se trouve ici.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Charge le fichier .env
load_dotenv()


# CHEMINS

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = DATA_DIR / "reports"
ZEEK_LOGS_DIR = DATA_DIR / "zeek_logs"
PCAPS_DIR = DATA_DIR / "pcaps"


# LLM / API

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    raise ValueError("GROQ_API_KEY manquante dans .env")
LLM_MODEL = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")  # modèle par défaut sur Groq
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.2"))


# NOMS DES AGENTS (centralisés)

AGENT_SUPERVISOR = "supervisor"
AGENT_HYPOTHESIS = "hypothesis_agent"
AGENT_NETWORK = "network_agent"
AGENT_IOC_CTI = "ioc_cti_agent"
AGENT_MITRE = "mitre_agent"


# SIEM (préparé pour plus tard)

SIEM_ENABLED = os.getenv("SIEM_ENABLED", "false").lower() == "true"
SIEM_TYPE = os.getenv("SIEM_TYPE", "wazuh")          # wazuh | elastic | ...
SIEM_URL = os.getenv("SIEM_URL", "")
SIEM_USER = os.getenv("SIEM_USER", "")
SIEM_PASSWORD = os.getenv("SIEM_PASSWORD", "")


# AUTRES

MAX_RELATED_EVENTS = 50