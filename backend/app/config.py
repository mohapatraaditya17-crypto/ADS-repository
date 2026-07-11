import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    # LLM configurations
    OPENAI_API_KEY: str = Field(default="mock-key")
    GEMINI_API_KEY: str = Field(default="mock-key")
    LLM_PROVIDER: str = Field(default="mock")
    LLM_MODEL: str = Field(default="mock-model")
    OLLAMA_BASE_URL: str = Field(default="http://localhost:11434")

    # Routing settings for agents
    LLM_PROVIDER_HEAVY: str = Field(default="gemini")
    LLM_MODEL_HEAVY: str = Field(default="gemini-2.0-flash")
    LLM_PROVIDER_LIGHT: str = Field(default="ollama")
    LLM_MODEL_LIGHT: str = Field(default="llama3.1")

    # Database configurations
    DB_HOST: str = Field(default="db")
    DB_PORT: int = Field(default=5432)
    DB_NAME: str = Field(default="falcon_copilot")
    DB_USER: str = Field(default="copilot")
    DB_PASSWORD: str = Field(default="copilot_secure_pass")
    EMBEDDING_DIM: int = Field(default=1536)

    # CrowdStrike API configurations (READ-ONLY)
    FALCON_CLIENT_ID: str = Field(default="mock-id")
    FALCON_CLIENT_SECRET: str = Field(default="mock-secret")
    FALCON_BASE_URL: str = Field(default="https://api.crowdstrike.com")

    # Server configurations
    PORT: int = Field(default=8000)
    HOST: str = Field(default="0.0.0.0")
    LOG_LEVEL: str = Field(default="info")

    # Pydantic Settings config
    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()

