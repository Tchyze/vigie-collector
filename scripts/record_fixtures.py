"""Enregistre (ou réenregistre) les réponses réelles des sources dans tests/fixtures/.

Usage : python scripts/record_fixtures.py [motif]

Les URL viennent de tests/fixtures/manifest.yaml. `trim` réduit les gros fichiers :
- head_lines: N  -> garde les N premières lignes d'un texte ;
- json_head: N   -> garde les N premiers éléments d'une liste JSON.
"""

import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vigie.http import HttpClient  # noqa: E402

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def trim(body: bytes, spec: dict | None) -> bytes:
    if not spec:
        return body
    if "head_lines" in spec:
        lines = body.decode("utf-8").splitlines(keepends=True)
        return "".join(lines[: spec["head_lines"]]).encode("utf-8")
    if "json_head" in spec:
        return json.dumps(json.loads(body)[: spec["json_head"]], ensure_ascii=False, indent=1).encode("utf-8")
    raise ValueError(f"trim inconnu : {spec}")


def main() -> None:
    pattern = sys.argv[1] if len(sys.argv) > 1 else ""
    manifest = yaml.safe_load((FIXTURES / "manifest.yaml").read_text(encoding="utf-8"))
    client = HttpClient()
    for entry in manifest:
        if pattern not in entry["file"] and pattern not in entry["url"]:
            continue
        response = client.get(entry["url"])
        target = FIXTURES / entry["file"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(trim(response.content, entry.get("trim")))
        print(f"{entry['url']} -> {entry['file']} ({target.stat().st_size} o)")


if __name__ == "__main__":
    main()
