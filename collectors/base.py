"""Interface commune des collecteurs."""

import datetime as dt
from dataclasses import dataclass

from vigie.catalog import Catalog
from vigie.http import HttpClient
from vigie.models import CollectResult


@dataclass
class Context:
    client: HttpClient
    catalog: Catalog
    today: dt.date
    # Dernier état enregistré de cette source (None au premier passage) : permet de ne
    # retélécharger que les nouveautés.
    previous: CollectResult | None = None


class CollectError(Exception):
    """Échec partiel : une partie des données a pu être collectée (`partial`)."""

    def __init__(self, message: str, partial: CollectResult):
        super().__init__(message)
        self.partial = partial


class Collector:
    """Un collecteur interroge une source et renvoie des objets normalisés.

    - `kind` : « versions » (branches) ou « advisories » (avis de sécurité) ;
    - `role` : « vendor » (source éditeur) ou « reference » (endoflife.date), pour la fusion.

    `collect` lève une exception si la source est inutilisable, ou `CollectError` avec les
    données partielles si une partie seulement a échoué.
    """

    name: str
    label: str
    kind: str
    role: str = "vendor"
    home: str
    attribution: str | None = None

    def collect(self, ctx: Context) -> CollectResult:
        raise NotImplementedError
