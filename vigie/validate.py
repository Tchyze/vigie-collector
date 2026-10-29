"""Validation des documents publiés contre les JSON Schema de schema/."""

import json
from functools import cache
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schema"

# Type de document -> fichier de schéma
SCHEMAS = {
    "index": "index.schema.json",
    "product": "product.schema.json",
    "advisories": "advisories.schema.json",
}


@cache
def validator(kind: str) -> Draft202012Validator:
    schema = json.loads((SCHEMA_DIR / SCHEMAS[kind]).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def errors(kind: str, document: dict) -> list[str]:
    """Liste lisible des erreurs de validation (vide si le document est valide)."""
    found = sorted(validator(kind).iter_errors(document), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<racine>'} : {e.message}" for e in found]
