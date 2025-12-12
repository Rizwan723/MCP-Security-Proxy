import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, Field
from functools import lru_cache
from typing import List, Union, Optional

class Settings(BaseSettings):
    """
    Centralized Configuration Management.
    Reads from environment variables (e.g., TOOL_FS_URL overrides tool_fs_url).
    """
    # Metadata
    app_name: str = "Secure MCP Bridge"
    debug: bool = False
    log_level: str = "INFO"

    # Scientific Parameters
    model_name: str = "distilbert-base-uncased"
    # The Sigma rule multiplier for anomaly thresholding (Standard: 3.0)
    detector_sigma: float = 3.0

    # MAML Detector Configuration
    maml_enabled: bool = False  # Enable MAML detector in ensemble
    maml_meta_lr: float = 0.001  # Meta-learning rate (outer loop)
    maml_inner_lr: float = 0.01  # Task adaptation learning rate (inner loop)
    maml_adaptation_steps: int = 5  # Gradient steps for task adaptation
    maml_first_order: bool = True  # Use first-order MAML (faster)
    maml_shots: int = 5  # Examples per class for adaptation
    maml_hidden_dim: int = 256  # Classifier hidden layer dimension
    maml_confidence_threshold: float = 0.6  # Min confidence for classification
    maml_num_meta_epochs: int = 100  # Meta-training epochs 

    # Service Discovery (Internal Docker URLs)
    # These defaults match your docker compose.yml service names
    # DEPRECATED: Use mcp_servers list instead
    tool_fs_url: str = "http://tool-filesystem:8080"
    tool_sql_url: str = "http://tool-sqlite:8080"
    tool_sandbox_url: str = "http://tool-exec:8080"

    # Dynamic MCP Server List
    # These URLs must match the service names in docker compose.yml
    # Can be set via MCP_SERVERS env var as comma-separated string
    # Note: Using Optional[str] for the validator to handle the raw env var first
    mcp_servers: Union[str, List[str]] = Field(
        default=[
            "http://tool-filesystem:8080",
            "http://tool-sqlite:8080",
            "http://tool-time:8080",
            "http://tool-fetch:8080",
            "http://tool-memory:8080",
        ]
    )

    @field_validator("mcp_servers", mode="before")
    @classmethod
    def parse_mcp_servers(cls, v: Union[str, List[str], None]) -> List[str]:
        """Parse MCP_SERVERS from comma-separated string or list."""
        if v is None or v == "":
            # Return default if not set
            return [
                "http://tool-filesystem:8080",
                "http://tool-sqlite:8080",
                "http://tool-time:8080",
                "http://tool-fetch:8080",
                "http://tool-memory:8080",
            ]
        if isinstance(v, str):
            # Handle empty string
            if not v.strip():
                return [
                    "http://tool-filesystem:8080",
                    "http://tool-sqlite:8080",
                    "http://tool-time:8080",
                    "http://tool-fetch:8080",
                    "http://tool-memory:8080",
                ]
            return [url.strip() for url in v.split(",") if url.strip()]
        return v

    # Persistence
    research_data_path: str = "/app/research_data"
    training_data_file: str = "training_dataset.json"
    semantic_model_path: str = "/app/trained_models/semantic_model.pt"
    statistical_model_path: str = "/app/trained_models/statistical_model.pt"
    maml_model_path: str = "/app/trained_models/maml_model.pt"
    audit_log_file: str = "runtime_audit.jsonl"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding='utf-8',
    )

@lru_cache()
def get_settings() -> Settings:
    """Singleton pattern for settings to avoid re-reading env vars."""
    return Settings()