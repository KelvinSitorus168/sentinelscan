from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_PENALTY = {"critical": 40, "high": 20, "medium": 10, "low": 3, "info": 0}


@dataclass
class Hit:
    """Raw result of a check: which catalog entry fired, plus evidence."""

    id: str
    evidence: str = ""
    severity: str | None = None  # optional override of the catalog default


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    why: str
    fix: str
    evidence: str = ""
    ref: str = ""


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    elapsed_ms: int = 0

    def get(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def get_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    @property
    def is_redirect(self) -> bool:
        return self.status in (301, 302, 303, 307, 308) and self.get("location") is not None
