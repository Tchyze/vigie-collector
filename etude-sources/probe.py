"""Sonde d'accès aux sources candidates (étude des sources, phase d'étude).

Lit candidats.tsv (id, méthode, URL, corps JSON facultatif), interroge chaque URL avec
l'identité du collecteur Vigie, au plus une requête par seconde et par hôte, et écrit :
- un tableau Markdown (URL / code HTTP / type / taille / durée / extrait) sur la sortie
  standard, ou dans $GITHUB_STEP_SUMMARY s'il existe ;
- un fichier JSON avec les mêmes mesures (--json).

Le corps est lu au plus jusqu'à MAX_BYTES : au-delà, la taille annoncée (Content-Length)
fait foi et la colonne « taille » porte « ≥ ». Aucune authentification, aucun contournement :
un 403 est consigné tel quel. Bibliothèque standard uniquement.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

USER_AGENT = "Vigie-collector/0.1 (+https://github.com/Tchyze/vigie-collector)"
TIMEOUT = 30
MAX_BYTES = 40 * 1024 * 1024
SNIPPET = 160


def load(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        rows.append(
            {
                "id": parts[0].strip(),
                "method": parts[1].strip().upper(),
                "url": parts[2].strip(),
                "body": parts[3].strip() if len(parts) > 3 and parts[3].strip() else None,
            }
        )
    return rows


def probe(row: dict) -> dict:
    data = row["body"].encode() if row["body"] else None
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(row["url"], data=data, method=row["method"], headers=headers)
    start = time.monotonic()
    result = {**row, "status": None, "content_type": None, "bytes": None, "truncated": False,
              "content_length": None, "final_url": None, "seconds": None, "snippet": "", "error": None}
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(MAX_BYTES + 1)
            result["status"] = resp.status
            result["final_url"] = resp.geturl()
            result["content_type"] = resp.headers.get("Content-Type")
            result["content_length"] = resp.headers.get("Content-Length")
    except urllib.error.HTTPError as exc:
        body = exc.read(4096) if exc.fp else b""
        result["status"] = exc.code
        result["content_type"] = exc.headers.get("Content-Type") if exc.headers else None
    except Exception as exc:  # noqa: BLE001 — on consigne toute erreur réseau
        body = b""
        result["error"] = f"{type(exc).__name__}: {exc}"[:200]
    result["seconds"] = round(time.monotonic() - start, 2)
    result["truncated"] = len(body) > MAX_BYTES
    result["bytes"] = min(len(body), MAX_BYTES)
    if not (result["content_type"] or "").startswith(("application/zip", "application/x-bzip", "application/gzip", "application/octet-stream", "application/x-gzip")):
        text = body[:SNIPPET * 2].decode("utf-8", "replace")
        result["snippet"] = " ".join(text.split())[:SNIPPET]
    return result


def human(n: int | None) -> str:
    if n is None:
        return "—"
    for unit in ("o", "Ko", "Mo", "Go"):
        if n < 1024 or unit == "Go":
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def markdown(results: list[dict], title: str) -> str:
    lines = [f"## {title}", "",
             "| id | méthode | URL | HTTP | type | taille | durée (s) | extrait / erreur |",
             "|---|---|---|---|---|---|---|---|"]
    for r in results:
        size = human(r["bytes"])
        if r["truncated"]:
            size = f"≥ {size}" + (f" (annoncé {human(int(r['content_length']))})" if r["content_length"] else "")
        extra = r["error"] or r["snippet"]
        extra = extra.replace("|", "\\|").replace("`", "'")
        ctype = (r["content_type"] or "—").split(";")[0]
        lines.append(f"| {r['id']} | {r['method']} | {r['url']} | {r['status'] or '—'} | {ctype} | {size} | {r['seconds']} | {extra} |")
    ok = sum(1 for r in results if r["status"] and 200 <= r["status"] < 300)
    lines += ["", f"{ok}/{len(results)} URL en 2xx."]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", default=str(Path(__file__).with_name("candidats.tsv")))
    parser.add_argument("--json", help="fichier JSON de résultats")
    parser.add_argument("--only", help="motif : ne sonder que les id qui le contiennent")
    parser.add_argument("--title", default="Accès aux sources candidates")
    args = parser.parse_args()

    rows = load(Path(args.candidates))
    if args.only:
        rows = [r for r in rows if any(p in r["id"] for p in args.only.split(","))]
    last_hit: dict[str, float] = {}
    results = []
    for row in rows:
        host = urllib.parse.urlsplit(row["url"]).hostname or ""
        wait = 1.0 - (time.monotonic() - last_hit.get(host, 0.0))
        if wait > 0:
            time.sleep(wait)
        res = probe(row)
        last_hit[host] = time.monotonic()
        results.append(res)
        print(f"{res['status'] or res['error']}\t{res['seconds']}s\t{human(res['bytes'])}\t{row['id']}", file=sys.stderr)

    md = markdown(results, args.title)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(md)
    print(md)
    if args.json:
        Path(args.json).write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
