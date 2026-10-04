from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    tool_name: str


@dataclass
class PolicyConfig:
    dangerous_verbs: List[str] = field(default_factory=list)
    read_only_prefixes: List[str] = field(default_factory=list)
    destructive_keywords: List[str] = field(default_factory=list)
    ingestion_keywords: List[str] = field(default_factory=list)
    execution_keywords: List[str] = field(default_factory=list)
    critical_sinks: List[str] = field(default_factory=list)
    high_risk_sinks: List[str] = field(default_factory=list)