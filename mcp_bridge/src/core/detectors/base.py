from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
from enum import Enum


class SecurityClass(str, Enum):
    """
    Binary security classification system for fast, accurate threat detection.

    BENIGN: Safe request - matches known good patterns, standard arguments,
            aligns with expected tool usage context.
    ATTACK: Malicious request - includes injection attacks, path traversal,
            command execution, anomalous patterns, and policy violations.
    """
    BENIGN = "benign"
    ATTACK = "attack"

    @property
    def is_allowed(self) -> bool:
        """Only BENIGN requests are automatically allowed."""
        return self == SecurityClass.BENIGN

    @property
    def description(self) -> str:
        descriptions = {
            SecurityClass.BENIGN: "Safe request matching known good patterns",
            SecurityClass.ATTACK: "Attack pattern detected"
        }
        return descriptions[self]


@dataclass
class DetectionResult:
    """
    Result of a binary security classification.

    classification: SecurityClass enum value (benign, attack)
    confidence: float 0.0 to 1.0 indicating detection confidence
    reason: human-readable explanation of the classification
    allowed: whether the request should be allowed (True only for BENIGN)
    metadata: additional data like distance to boundary, detector scores, etc.
    """
    classification: str  # SecurityClass value: "benign", "attack"
    confidence: float
    reason: str
    allowed: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def benign(cls, confidence: float, reason: str, metadata: Optional[Dict[str, Any]] = None) -> "DetectionResult":
        """Create a BENIGN (allowed) detection result."""
        return cls(SecurityClass.BENIGN.value, confidence, reason, True, metadata or {})

    @classmethod
    def attack(cls, confidence: float, reason: str, metadata: Optional[Dict[str, Any]] = None) -> "DetectionResult":
        """Create an ATTACK (blocked) detection result."""
        return cls(SecurityClass.ATTACK.value, confidence, reason, False, metadata or {})


class BaseDetector(ABC):
    """Abstract Base Class for all detection strategies."""

    @abstractmethod
    def predict(self, payload: str, tool_name: Optional[str] = None) -> Optional[DetectionResult]:
        """
        Analyze the payload and return a binary detection result.
        Returns None if the detector abstains (e.g., not applicable).

        Classifications:
        - BENIGN: Safe request, matches known good patterns
        - ATTACK: Malicious request (injection, traversal, anomaly, policy violation)
        """
        pass

    @abstractmethod
    def fit(self, tool_name: str, benign_samples: List[str],
            attack_samples: Optional[List[str]] = None):
        """
        Train the detector with labeled samples.

        Args:
            tool_name: Name of the tool being trained
            benign_samples: Known safe requests
            attack_samples: Known attack patterns (injections, traversals, anomalies)
        """
        pass

    @abstractmethod
    def save_state(self) -> Dict[str, Any]:
        """Return state for persistence."""
        pass

    @abstractmethod
    def load_state(self, state: Dict[str, Any]):
        """Load state from persistence."""
        pass
