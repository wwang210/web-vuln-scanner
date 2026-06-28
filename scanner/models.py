from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def order(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]


@dataclass
class Finding:
    vuln_type: str
    severity: Severity
    url: str
    evidence: str
    method: str
    parameter: str | None = None

    def __lt__(self, other: "Finding") -> bool:
        return self.severity.order < other.severity.order
