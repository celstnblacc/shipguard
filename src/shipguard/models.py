"""Data models for ShipGuard findings and scan results."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }[self]

    def __ge__(self, other: Severity) -> bool:
        return self.rank >= other.rank

    def __gt__(self, other: Severity) -> bool:
        return self.rank > other.rank

    def __le__(self, other: Severity) -> bool:
        return self.rank <= other.rank

    def __lt__(self, other: Severity) -> bool:
        return self.rank < other.rank


@dataclass
class Finding:
    """A single security finding."""

    rule_id: str
    severity: Severity
    file_path: Path
    line_number: int
    line_content: str
    message: str
    cwe_id: str | None = None
    fix_hint: str | None = None
    is_false_positive: bool = False
    ai_triage_reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "line_content": self.line_content,
            "message": self.message,
            "cwe_id": self.cwe_id,
            "fix_hint": self.fix_hint,
            "is_false_positive": self.is_false_positive,
            "ai_triage_reason": self.ai_triage_reason,
        }


@dataclass
class ScanResult:
    """Aggregated scan results."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    rules_applied: int = 0
    duration_seconds: float = 0.0
    scan_root: Path | None = field(default=None)
    discovered_files: list[Path] = field(default_factory=list)
    _start_time: float = field(default_factory=time.monotonic, repr=False, init=False)

    def finish(self) -> None:
        self.duration_seconds = time.monotonic() - self._start_time

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                **self.summary,
                "total": len(self.findings),
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "rules_applied": self.rules_applied,
                "duration_seconds": round(self.duration_seconds, 3),
            },
        }
