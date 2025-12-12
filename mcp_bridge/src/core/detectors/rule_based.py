import re
import logging
from typing import List, Tuple, Optional, Dict, Any
from .base import BaseDetector, DetectionResult, SecurityClass

logger = logging.getLogger(__name__)

# Maximum payload length to process (ReDoS prevention)
MAX_PAYLOAD_LENGTH = 10000


class RuleBasedDetector(BaseDetector):
    """
    Deterministic pattern matching for known attack signatures.

    Binary classification:
    - ATTACK: Known attack patterns (injection, traversal, command execution, policy violations)
    - Defers to other detectors when no patterns match

    High precision, low recall for novel attacks.
    Returns None for requests that don't match any patterns (defers to other detectors).

    Security Note:
    - Patterns are designed to avoid catastrophic backtracking (ReDoS)
    - Input length is limited to MAX_PAYLOAD_LENGTH characters
    - Unbounded quantifiers are avoided in favor of bounded ones
    """

    def __init__(self):
        self._compile_attack_patterns()

    def _compile_attack_patterns(self):
        """
        Compile regex patterns for known attacks (ATTACK class).
        Includes injection attacks, command execution, policy violations, and sensitive access.
        """
        self.attack_patterns = {
            'path_traversal': [
                r'\.\./\.\./\.\.',           # ../../../
                r'\.\.\\\.\.\\',             # ..\..\ (Windows)
                r'\.\.%2[fF]',               # URL encoded
                r'\.\.%5[cC]',               # URL encoded backslash
                r'%2e%2e[/\\]',              # Double encoded
                r'\.\.\.\.//\.\.\.\./',      # ....//....//
            ],
            'command_injection': [
                r';\s{0,10}(?:rm|cat|ls|nc|wget|curl|bash|sh|python|perl)',  # ; rm, ; cat, etc.
                r'\|\s{0,10}(?:nc|netcat|bash|sh)',                           # | nc, | bash
                r'`[^`]{0,100}(?:rm|cat|ls|id|whoami|pwd)',                   # `whoami` (bounded)
                r'\$\([^)]{0,100}(?:rm|cat|ls|id|whoami|curl|wget)',          # $(whoami) (bounded)
                r'&&\s{0,10}(?:rm|cat|ls|nc|curl|wget)',                      # && rm
                r'\$\{IFS\}',                                                  # ${IFS} bypass
                r'\\x00',                                                      # Null byte injection
            ],
            'sql_injection': [
                r"UNION\s{1,10}SELECT",                                   # Union injection (bounded)
                r"OR\s{1,10}['\"]?1['\"]?\s{0,5}=\s{0,5}['\"]?1",       # OR '1'='1' (bounded)
                r";\s{0,10}(?:DROP|DELETE|UPDATE|INSERT)",               # Stacked queries
                r"--\s{0,5}$",                                            # SQL comments at end
                r"'\s{0,10}OR\s{1,10}'\w{1,30}'\s{0,5}=\s{0,5}'\w{1,30}", # OR injection (bounded)
                r"EXEC\s{1,10}(?:xp_|sp_)",                              # SQL Server procs
                r"WAITFOR\s{1,10}DELAY",                                  # Time-based blind
                r"SLEEP\s{0,5}\(",                                        # MySQL sleep
                r"information_schema",                                    # Schema enumeration
                r"LOAD_FILE\s{0,5}\(",                                    # File read
                r"INTO\s{1,10}(?:OUTFILE|DUMPFILE)",                     # File write
                r"/\*\*/",                                                # Comment bypass
            ],
            'system_files': [
                r'/etc/(?:passwd|shadow|sudoers|hosts|crontab)',         # Unix sensitive
                r'C:\\Windows\\System32',                                # Windows system
                r'/proc/(?:self|1)/',                                    # Process info
                r'/root/\.ssh',                                           # SSH keys
                r'\.ssh/id_rsa',                                         # Private keys
                r'/dev/tcp/',                                             # Bash network
                r'/var/run/secrets',                                      # Kubernetes secrets
                r'/sys/kernel',                                           # Kernel info
            ],
            'xxe_attacks': [
                r'<!ENTITY',                                              # XML entity
                r'SYSTEM\s+["\']file://',                                # File protocol
                r'php://filter',                                          # PHP wrapper
                r'expect://',                                             # Expect wrapper
                r'data://',                                               # Data wrapper
            ],
            'ssrf_attacks': [
                r'http://(?:localhost|127\.0\.0\.1)',                    # Localhost
                r'http://(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)',  # Private IPs
                r'http://169\.254\.169\.254',                            # AWS metadata
                r'http://metadata\.google\.internal',                    # GCP metadata
                r'http://\[::1\]',                                       # IPv6 localhost
                r'(?:file|gopher|dict)://',                              # Dangerous protocols
                r'http://kubernetes\.default',                            # Kubernetes API
                r'http://(?:0\.0\.0\.0|0x7f)',                           # Alternative localhost
            ],
            'xss_injection': [
                r'<script[^>]{0,100}>',                                   # Script tags (bounded)
                r'onerror\s{0,5}=',                                       # Event handlers
                r'javascript:',                                           # JS protocol
                r'\{\{.{0,50}constructor',                                # Template injection (bounded)
            ],
            'secrets_access': [
                r'secret[s]?[/\\]',                    # secret/ or secrets/
                r'\.env',                               # .env files
                r'(?:api[_-]?key|password|token|credential)',  # Credential keywords
                r'private[_-]?key',                     # Private keys
                r'id_rsa',                              # SSH keys
            ],
            'destructive_operations': [
                r'(?:DROP|TRUNCATE)\s{1,10}(?:TABLE|DATABASE)',  # Destructive SQL (bounded)
                r'DELETE\s{1,10}FROM\s{1,10}(?:users|admins|logs)',   # Sensitive deletions
                r'GRANT\s{1,10}ALL',                              # Privilege escalation
                r'CREATE\s{1,10}USER',                            # User creation
                r'UPDATE\s{1,10}users\s{1,10}SET\s{1,10}(?:role|admin|password)',  # Privilege changes
            ],
            'bulk_data_exfiltration': [
                r'DELETE\s{1,10}FROM\s{1,10}\w{1,50}\s{0,5}(?:WHERE\s{1,10}1\s{0,5}=\s{0,5}1)?$',  # Mass deletion (bounded)
                r'SELECT\s{1,10}\*\s{1,10}FROM\s{1,10}(?:users|customers|orders|payments)',  # Bulk PII access
            ],
        }

        self.compiled_attack_patterns = []
        for category, patterns in self.attack_patterns.items():
            for pattern in patterns:
                try:
                    self.compiled_attack_patterns.append((category, re.compile(pattern, re.IGNORECASE)))
                except re.error as e:
                    logger.warning(f"Failed to compile attack pattern {pattern}: {e}")

    def _check_patterns(self, payload: str, pattern_list: List[Tuple[str, re.Pattern]]) -> Tuple[bool, str]:
        """Check payload against pattern list, return (matched, category)."""
        for category, pattern in pattern_list:
            if pattern.search(payload):
                return True, category
        return False, ""

    def predict(self, payload: str, tool_name: Optional[str] = None) -> Optional[DetectionResult]:
        """
        Check payload against known attack patterns.

        Returns:
            - ATTACK for known attack patterns (injection, traversal, policy violations)
            - ATTACK if payload exceeds MAX_PAYLOAD_LENGTH (suspicious)
            - None if no patterns match (defers to other detectors)
        """
        # ReDoS prevention: reject excessively long payloads
        if len(payload) > MAX_PAYLOAD_LENGTH:
            logger.warning(f"Payload exceeds max length ({len(payload)} > {MAX_PAYLOAD_LENGTH})")
            return DetectionResult.attack(
                confidence=0.80,
                reason=f"Payload exceeds maximum length ({len(payload)} chars)",
                metadata={"pattern_category": "oversized_payload", "detector": "rule_based"}
            )

        is_attack, attack_type = self._check_patterns(payload, self.compiled_attack_patterns)
        if is_attack:
            return DetectionResult.attack(
                confidence=0.95,
                reason=f"Known attack pattern: {attack_type}",
                metadata={"pattern_category": attack_type, "detector": "rule_based"}
            )

        # No patterns matched - defer to other detectors
        return None

    def fit(self, tool_name: str, benign_samples: List[str],
            attack_samples: Optional[List[str]] = None):
        """Rule-based detector is static - no training needed."""
        pass

    def save_state(self) -> Dict[str, Any]:
        """Return state for persistence."""
        return {"version": "2.0", "type": "binary"}

    def load_state(self, state: Dict[str, Any]):
        """Load state from persistence."""
        pass
