"""Outils partagés : nettoyage HTML, résumés courts, dates, CVE, sévérités."""

import calendar
import datetime as dt
import html
import re
import time

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_TAG_RE = re.compile(r"<[^>]+>")
_SPACE_RE = re.compile(r"\s+")
MONTHS = {name: number for number, name in enumerate(calendar.month_abbr) if name}
SUMMARY_MAX = 300


def strip_html(text: str | None) -> str:
    if not text:
        return ""
    text = html.unescape(_TAG_RE.sub(" ", text))
    text = html.unescape(_TAG_RE.sub(" ", text))  # certains flux échappent deux fois leur HTML
    return _SPACE_RE.sub(" ", text).strip()


def short_summary(text: str | None, limit: int = SUMMARY_MAX) -> str | None:
    """Coupe un texte à la dernière phrase complète qui tient dans `limit` caractères."""
    text = strip_html(text)
    if not text:
        return None
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    end = max(cut.rfind(". "), cut.rfind(".\n"))
    if end >= limit // 3:
        return cut[: end + 1]
    return cut[: cut.rfind(" ")].rstrip(" ,;:") + "…"


def cves(text: str | None) -> list[str]:
    return list(dict.fromkeys(CVE_RE.findall(text or "")))


def utc_from_struct(value: time.struct_time | None) -> str | None:
    """feedparser fournit des struct_time déjà ramenés en UTC."""
    if value is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", value)


def date_from_struct(value: time.struct_time | None) -> str | None:
    return time.strftime("%Y-%m-%d", value) if value else None


def tag_name(entry) -> str:
    """Nom d'un tag dans un flux Atom GitHub (tags.atom).

    Le titre d'un tag annoté contient aussi son message (« V_10_0_P2: openssh-10.0p2 ») ;
    l'identifiant, lui, se termine toujours par le nom seul.
    """
    return (entry.get("id") or entry.get("title") or "").rsplit("/", 1)[-1].strip()


def parse_day_month_year(text: str) -> str:
    """« 21 Oct 2026 » -> « 2026-10-21 », indépendamment de la locale."""
    day, month, year = text.split()
    return dt.date(int(year), MONTHS[month[:3].title()], int(day)).isoformat()


def iso_utc(value: str) -> str:
    """Horodatage ISO quelconque -> AAAA-MM-JJThh:mm:ssZ en UTC."""
    moment = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


SEVERITIES = {
    "critical": "critical", "critique": "critical",
    "high": "high", "élevée": "high", "elevee": "high",
    "medium": "medium", "moderate": "medium", "moyenne": "medium",
    "low": "low", "faible": "low",
    "informational": "info", "info": "info", "none": "info",
}


def normalize_severity(value: str | None) -> str | None:
    return SEVERITIES.get((value or "").strip().lower())


def severity_from_cvss(score: float | None) -> str | None:
    """Barème CVSS v3 : 0 aucune, < 4 faible, < 7 moyenne, < 9 élevée, sinon critique."""
    if score is None:
        return None
    if score == 0:
        return "info"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def change_summary(counts: dict[str, int], security_cves: list[str]) -> str | None:
    """Résumé d'un changelog à partir du décompte de ses entrées, sans en recopier le texte."""
    parts = []
    if counts.get("security"):
        detail = ""
        if security_cves:
            shown = security_cves[:6]
            detail = " (" + ", ".join(shown) + (", …" if len(security_cves) > len(shown) else "") + ")"
        parts.append(f"{counts['security']} correctif(s) de sécurité{detail}")
    labels = (("feature", "nouveauté(s)"), ("change", "changement(s)"), ("bugfix", "correction(s)"))
    parts += [f"{counts[key]} {label}" for key, label in labels if counts.get(key)]
    return short_summary(", ".join(parts)) if parts else None
