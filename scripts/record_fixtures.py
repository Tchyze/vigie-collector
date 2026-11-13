"""Enregistre (ou réenregistre) les réponses réelles des sources dans tests/fixtures/.

Usage : python scripts/record_fixtures.py [motif]

Les URL viennent de tests/fixtures/manifest.yaml (`headers` : en-têtes de la requête ; `post` :
corps JSON d'une requête POST ; tous deux facultatifs). `trim` réduit les gros fichiers :
- head_lines: N  -> garde les N premières lignes d'un texte ;
- json_head: N   -> garde les N premiers éléments d'une liste JSON ;
- json_key_head: {key: K, n: N, drop: [champs]} -> garde les N premiers éléments de la liste
  data[K], sans les champs listés dans `drop`, et les listes de `truncate` ({champ: N}) coupées ;
- json_dict_filter: {field: F, contains: T, others: N} -> dictionnaire JSON réduit aux entrées dont
  le champ F contient T, plus N autres ;
- dell_catalog: N -> catalogue Dell (XML UTF-16 compressé) réduit aux firmwares iDRAC, plus N
  autres composants ;
- cvrf_sample: N -> document CVRF Microsoft réduit à N vulnérabilités de chaque sorte (critique,
  importante, exploitée, hors Windows Server), l'arbre des produits restant complet.
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
    if "json_key_head" in spec:
        data = json.loads(body)
        key, n = spec["json_key_head"]["key"], spec["json_key_head"]["n"]
        drop = set(spec["json_key_head"].get("drop") or [])
        truncate = spec["json_key_head"].get("truncate") or {}
        data[key] = [
            {k: (v[: truncate[k]] if k in truncate else v) for k, v in item.items() if k not in drop}
            for item in data[key][:n]
        ]
        return json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8")
    if "json_dict_filter" in spec:
        rule, data, others = spec["json_dict_filter"], json.loads(body), 0
        kept = {}
        for key, value in data.items():
            if rule["contains"] in str(value.get(rule["field"]) or ""):
                kept[key] = value
            elif others < rule["others"]:
                kept[key], others = value, others + 1
        return json.dumps(kept, ensure_ascii=False, indent=1).encode("utf-8")
    if "dell_catalog" in spec:
        return dell_catalog(body, spec["dell_catalog"])
    if "cvrf_sample" in spec:
        return cvrf_sample(json.loads(body), spec["cvrf_sample"])
    raise ValueError(f"trim inconnu : {spec}")


def dell_catalog(body: bytes, others: int) -> bytes:
    import gzip
    import xml.etree.ElementTree as ET

    root = ET.fromstring(gzip.decompress(body))
    for component in list(root.findall("SoftwareComponent")):
        if (component.findtext("Name/Display") or "").startswith("iDRAC "):
            continue
        if others > 0:
            others -= 1
            continue
        root.remove(component)
    for bundle in list(root.findall("SoftwareBundle")):
        root.remove(bundle)
    return gzip.compress(ET.tostring(root, encoding="utf-16"), mtime=0)


def cvrf_sample(data: dict, n: int) -> bytes:
    servers = {p["ProductID"] for p in data["ProductTree"]["FullProductName"] if p["Value"].startswith("Windows Server")}
    buckets: dict[str, list] = {"critical": [], "important": [], "exploited": [], "other": []}
    for vuln in data["Vulnerability"]:
        affected = {p for s in vuln["ProductStatuses"] if s["Type"] == 3 for p in s["ProductID"]}
        threats = " ".join(t["Description"]["Value"] for t in vuln["Threats"] if affected & servers & set(t.get("ProductID") or []))
        exploited = any("Exploited:Yes" in t["Description"]["Value"] for t in vuln["Threats"] if t["Type"] == 1)
        kind = ("exploited" if exploited else "critical" if "Critical" in threats
                else "important" if affected & servers else "other")
        if len(buckets[kind]) < n:
            buckets[kind].append(vuln)
    data["Vulnerability"] = [v for bucket in buckets.values() for v in bucket]
    return json.dumps(data, ensure_ascii=False).encode("utf-8")


def main() -> None:
    pattern = sys.argv[1] if len(sys.argv) > 1 else ""
    manifest = yaml.safe_load((FIXTURES / "manifest.yaml").read_text(encoding="utf-8"))
    client = HttpClient()
    for entry in manifest:
        if pattern not in entry["file"] and pattern not in entry["url"]:
            continue
        if "post" in entry:
            response = client.request("POST", entry["url"], headers=entry.get("headers"), json=entry["post"])
        else:
            response = client.get(entry["url"], headers=entry.get("headers"))
        target = FIXTURES / entry["file"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(trim(response.content, entry.get("trim")))
        print(f"{entry['url']} -> {entry['file']} ({target.stat().st_size} o)")


if __name__ == "__main__":
    main()
