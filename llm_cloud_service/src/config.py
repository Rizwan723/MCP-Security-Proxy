from pydantic_settings import BaseSettings
from typing import Literal

class Settings(BaseSettings):
    """
    Configuration for Cloud LLM Service.
    All parameters can be overridden via environment variables with CLOUD_ prefix.
    """
    # Provider Selection: 'openai' or 'gemini'
    llm_provider: Literal["openai", "gemini"] = "openai"
    
    # Credentials
    openai_api_key: str = ""
    google_api_key: str = ""
    
    # Model Selection
    # Examples: "gpt-3.5-turbo", "gpt-4", "gemini-pro"
    model_name: str = "gpt-3.5-turbo"
    
    # Generation Parameters
    temperature: float = 0.7
    max_tokens: int = 1024

    class Config:
        env_file = ".env"
        env_prefix = "CLOUD_"

settings = Settings()