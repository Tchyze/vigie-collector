"""Cisco IOS XE : versions publiées et versions de correctif, depuis l'API Cisco PSIRT openVuln.

Accès : OAuth2 « client credentials ». Les identifiants viennent des variables d'environnement
CISCO_CLIENT_ID et CISCO_CLIENT_SECRET (secrets de l'environnement GitHub « main ») ; sans elles,
le collecteur échoue avec un message clair et Vigie garde le dernier état publié. Le jeton
(valable 1 h) est redemandé à chaque passage et n'est jamais enregistré.

1. `OS_version/OS_data?OSType=iosxe` : toutes les versions IOS XE connues du Cisco Software
   Checker, sans date. On ne garde que les versions courantes (17.12.8) et leurs reconstructions
   (17.12.7b) ; les versions spéciales (17.12.1z5, 17.18.5x, 26.1.2s1) sont ignorées.
2. `OSType/iosxe?version=<première version de la branche>` : avis qui touchent la branche, avec
   `firstFixed`, les premières versions corrigées. Une version de la branche qui y figure est un
   correctif de sécurité (security_fix = true). Les autres restent inconnues (null) : une faille
   apparue après la première version de la branche n'est pas vue par cette requête.

Les branches antérieures à la 17 ne sont pas interrogées (une requête par branche ; limite de
l'API : 5 appels par seconde, 60 par minute).

Conditions d'utilisation : citer Cisco comme source ; usage non commercial.
"""

import os
import re

import httpx

from collectors.base import CollectError, Collector, Context
from collectors.cisco import ATTRIBUTION
from vigie.models import BranchData, CollectResult, Release
from vigie.versions import token_key

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
API = "https://apix.cisco.com/security/advisories/v2/"
OS_DATA = API + "OS_version/OS_data?OSType=iosxe"
BY_VERSION = API + "OSType/iosxe?version={version}"
PRODUCT = "cisco-ios-xe"
REGULAR = re.compile(r"^(\d+)\.(\d+)\.\d+[a-h]?$")
MIN_MAJOR = 17


class CiscoOpenVuln(Collector):
    name = "cisco_openvuln"
    label = "Cisco PSIRT openVuln (versions IOS XE)"
    kind = "versions"
    home = "https://developer.cisco.com/docs/psirt/"
    attribution = ATTRIBUTION

    def collect(self, ctx: Context) -> CollectResult:
        client_id, secret = os.environ.get("CISCO_CLIENT_ID"), os.environ.get("CISCO_CLIENT_SECRET")
        if not (client_id and secret):
            raise RuntimeError("identifiants absents (CISCO_CLIENT_ID, CISCO_CLIENT_SECRET)")
        token = ctx.client.post_form(TOKEN_URL, {
            "grant_type": "client_credentials", "client_id": client_id, "client_secret": secret,
        })["access_token"]
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        versions = [item["nos_version"] for item in ctx.client.json(OS_DATA, headers=headers)
                    if isinstance(item, dict) and item.get("nos_version")]
        branches = group_by_branch(versions)
        if not branches:
            raise ValueError("aucune version IOS XE dans OS_data")

        errors = []
        for name, branch in branches.items():
            if int(name.split(".")[0]) < MIN_MAJOR:
                continue
            first = min((r.version for r in branch.releases), key=token_key)
            try:
                advisories = advisories_for(ctx, first, headers)
            except httpx.HTTPError as exc:
                errors.append(f"{name} : {exc}")
                continue
            mark_security_fixes(branch, advisories)

        result = CollectResult(branches=list(branches.values()))
        if errors:
            raise CollectError(f"avis indisponibles pour {len(errors)} branche(s) : {errors[0]}", result)
        return result


def group_by_branch(versions: list[str]) -> dict[str, BranchData]:
    """{« 17.12 » : BranchData} avec les versions courantes de chaque branche."""
    branches: dict[str, BranchData] = {}
    for version in versions:
        match = REGULAR.match(version.strip())
        if not match:
            continue
        name = f"{match[1]}.{match[2]}"
        branch = branches.setdefault(name, BranchData(product=PRODUCT, branch=name))
        if all(r.version != match[0] for r in branch.releases):
            branch.releases.append(Release(version=match[0]))
    return branches


def advisories_for(ctx: Context, version: str, headers: dict) -> list[dict]:
    """Avis qui touchent `version` ; une version sans avis peut répondre 404."""
    try:
        data = ctx.client.json(BY_VERSION.format(version=version), headers=headers)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return []
        raise
    return (data.get("advisories") if isinstance(data, dict) else None) or []


def mark_security_fixes(branch: BranchData, advisories: list[dict]) -> None:
    """security_fix = true pour chaque version de la branche citée dans un `firstFixed`."""
    fixes = set()
    for advisory in advisories:
        for version in advisory.get("firstFixed") or []:
            match = REGULAR.match(str(version).strip())
            if match and f"{match[1]}.{match[2]}" == branch.branch:
                fixes.add(match[0])
    known = {r.version: r for r in branch.releases}
    for version in fixes:
        if version not in known:  # correctif absent d'OS_data : on l'ajoute
            known[version] = Release(version=version)
            branch.releases.append(known[version])
        known[version].security_fix = True


COLLECTOR = CiscoOpenVuln()
