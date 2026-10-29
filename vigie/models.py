"""Objets normalisés échangés entre les collecteurs et build.py."""

from dataclasses import asdict, dataclass, field, fields

EOL_KEYS = (
    "end_of_active_support",
    "end_of_security_support",
    "end_of_life",
    "end_of_extended_support",
)


@dataclass
class Release:
    version: str
    date: str | None = None
    security_fix: bool | None = None
    summary: str | None = None
    url: str | None = None


@dataclass
class BranchData:
    """Ce qu'une source sait d'une branche. Tout champ peut rester vide : build.py fusionne."""

    product: str
    branch: str
    label: str | None = None
    lts: bool | None = None
    release_date: str | None = None
    eol_dates: dict[str, str | None] = field(default_factory=dict)
    eol_labels: dict[str, str] = field(default_factory=dict)
    eol_source_url: str | None = None
    declared_eol: bool | None = None
    releases: list[Release] = field(default_factory=list)

    @property
    def id(self) -> str:
        return branch_id(self.product, self.branch)


@dataclass
class Advisory:
    id: str
    source: str
    vendor: str
    title: str
    published: str
    url: str
    updated: str | None = None
    severity: str | None = None
    cvss: float | None = None
    cves: list[str] = field(default_factory=list)
    summary: str | None = None
    affected: list[str] = field(default_factory=list)
    attribution: str | None = None


@dataclass
class CollectResult:
    branches: list[BranchData] = field(default_factory=list)
    advisories: list[Advisory] = field(default_factory=list)

    def count(self) -> int:
        return len(self.branches) + len(self.advisories)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CollectResult":
        branches = []
        for raw in data.get("branches", []):
            raw = _known(BranchData, raw)
            raw["releases"] = [Release(**_known(Release, r)) for r in raw.get("releases", [])]
            branches.append(BranchData(**raw))
        advisories = [Advisory(**_known(Advisory, a)) for a in data.get("advisories", [])]
        return cls(branches=branches, advisories=advisories)


def branch_id(product: str, branch: str) -> str:
    return f"{product}-{branch}".lower().replace(" ", "-")


def _known(cls, raw: dict) -> dict:
    """Ignore les clés inconnues d'un état enregistré par une version antérieure."""
    names = {f.name for f in fields(cls)}
    return {k: v for k, v in raw.items() if k in names}
