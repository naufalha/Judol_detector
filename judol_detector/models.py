"""Data models untuk Judol Detector."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class DetectedDomain:
    """Domain yang terdeteksi sebagai judol."""
    domain: str
    confidence: float  # 0.0 - 1.0
    reason: str
    detected_at: datetime = field(default_factory=datetime.now)
    is_blocked: bool = False


@dataclass
class AnalyzedDomain:
    """Domain yang sudah dianalisis (judol atau bukan)."""
    domain: str
    is_judol: bool
    confidence: float
    reason: str
    analyzed_at: datetime = field(default_factory=datetime.now)


@dataclass
class ScanResult:
    """Hasil dari satu kali scan."""
    scan_id: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.now)
    total_queries: int = 0
    unique_domains: int = 0
    new_domains: int = 0  # belum pernah dianalisis
    detected_judol: int = 0
    blocked: int = 0
    detected_domains: list[DetectedDomain] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
