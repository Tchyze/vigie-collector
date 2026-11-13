"""Accès à l'API Cisco PSIRT openVuln, commun aux collecteurs `cisco` et `cisco_openvuln`.

OAuth2 « client credentials » : les identifiants viennent des variables d'environnement
CISCO_CLIENT_ID et CISCO_CLIENT_SECRET (secrets de l'environnement GitHub « main »). Ils sont
envoyés dans le corps de la requête de jeton, jamais dans une URL ; le jeton (valable 1 h) est
redemandé à chaque passage et n'est jamais enregistré. Limite de l'API : 5 appels/s, 60/min.
"""

import os

from vigie.http import HttpClient

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
API = "https://apix.cisco.com/security/advisories/v2/"


def has_credentials() -> bool:
    return bool(os.environ.get("CISCO_CLIENT_ID") and os.environ.get("CISCO_CLIENT_SECRET"))


def auth_headers(client: HttpClient) -> dict:
    """En-têtes d'une requête authentifiée ; RuntimeError si les identifiants manquent."""
    client_id, secret = os.environ.get("CISCO_CLIENT_ID"), os.environ.get("CISCO_CLIENT_SECRET")
    if not (client_id and secret):
        raise RuntimeError("identifiants absents (CISCO_CLIENT_ID, CISCO_CLIENT_SECRET)")
    token = client.post_form(TOKEN_URL, {
        "grant_type": "client_credentials", "client_id": client_id, "client_secret": secret,
    })["access_token"]
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}
