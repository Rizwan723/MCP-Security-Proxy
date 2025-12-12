import json
import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Optional

# Configure root logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger("MCP_Audit")

# Audit log path from environment or default
AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "/app/research_data/runtime_audit.jsonl")
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB per file
BACKUP_COUNT = 5  # Keep 5 rotated files


class NumpyEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles numpy types."""
    def default(self, obj):
        if hasattr(obj, 'tolist'):
            return obj.tolist()
        if hasattr(obj, 'item'):
            return obj.item()
        return super().default(obj)


class AuditLogger:
    """
    Singleton audit logger with log rotation support.
    Provides structured JSONL logging for thesis analysis.
    """
    _instance: Optional['AuditLogger'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.log_path = AUDIT_LOG_PATH
        self._ensure_log_directory()
        self._setup_rotating_logger()
        self._initialized = True
        logger.info(f"Audit logger initialized: {self.log_path}")

    def _ensure_log_directory(self):
        """Create log directory if it doesn't exist."""
        log_dir = os.path.dirname(self.log_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

    def _setup_rotating_logger(self):
        """Configure rotating file handler for JSONL audit logs."""
        self.audit_logger = logging.getLogger("thesis_audit")
        self.audit_logger.setLevel(logging.INFO)
        self.audit_logger.propagate = False

        # Remove existing handlers to avoid duplicates
        self.audit_logger.handlers.clear()

        # Create rotating file handler
        handler = RotatingFileHandler(
            self.log_path,
            maxBytes=MAX_LOG_SIZE,
            backupCount=BACKUP_COUNT,
            encoding='utf-8'
        )
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.audit_logger.addHandler(handler)

    def log(self, request_id: str, tool: str, payload: str, result: dict,
            latency_ms: Optional[float] = None):
        """
        Log a detection event with full context for thesis analysis.

        Args:
            request_id: Unique request identifier
            tool: MCP tool name that was called
            payload: The request payload (will be truncated)
            result: Detection result dict with class, confidence, etc.
            latency_ms: Optional detection latency in milliseconds
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": str(request_id),
            "tool": tool,
            "payload_full": payload,  # Store full payload for analysis
            "payload_length": len(payload),
            "classification": result.get("class", "unknown"),
            "confidence": float(result.get("confidence", 0.0)),
            "distances": result.get("distances", {}),
            "reason": result.get("reason", ""),
            "decision": "BLOCK" if not result.get("allowed", False) else "ALLOW",
            "latency_ms": latency_ms
        }

        try:
            self.audit_logger.info(json.dumps(entry, cls=NumpyEncoder))
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create the singleton audit logger."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def log_thesis_data(request_id: str, tool: str, payload: str, result: dict,
                   latency_ms: Optional[float] = None):
    """
    Saves interaction data to a JSONL file for thesis analysis.
    Uses rotating log files to prevent unbounded growth.

    Args:
        request_id: Unique request identifier
        tool: MCP tool name that was called
        payload: The request payload
        result: Detection result dict
        latency_ms: Optional detection latency in milliseconds
    """
    audit_logger = get_audit_logger()
    audit_logger.log(request_id, tool, payload, result, latency_ms)
