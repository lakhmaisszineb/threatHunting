"""
Constantes partagées du projet.
Évite la duplication de chaînes magiques.
"""

# Noms des logs Zeek
ZEEK_CONN = "conn"
ZEEK_DNS = "dns"
ZEEK_WEIRD = "weird"
ZEEK_HTTP = "http"

ZEEK_KEY = "zeek"

# Champs Zeek courants
FIELD_SRC_IP = "id.orig_h"
FIELD_DST_IP = "id.resp_h"
FIELD_SRC_PORT = "id.orig_p"
FIELD_DST_PORT = "id.resp_p"
FIELD_CONN_STATE = "conn_state"

# États de connexion considérés comme échoués
FAILED_CONN_STATES = {"S0", "REJ", "RSTO", "RSTOS0", "RSTR", "OTH"}