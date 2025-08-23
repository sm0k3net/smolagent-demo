from __future__ import annotations
import os
from dotenv import load_dotenv  # type: ignore
from functools import lru_cache
from pydantic import BaseModel

class Settings(BaseModel):
    deepseek_api_key: str | None = None
    deepseek_api_url: str = "https://api.deepseek.com/v1/chat/completions"
    deepseek_api_base: str | None = os.getenv("DEEPSEEK_API_BASE")  # e.g. https://api.deepseek.com/v1
    model: str = "deepseek-chat"
    searxng_base_url: str | None = os.getenv("SEARXNG_BASE_URL")  # e.g. https://searxng.example.org
    searxng_headers: dict[str, str] = {}
    environment: str = os.getenv("ENV", "dev")
    prompt_path: str | None = os.getenv("PROMPT_PATH")  # optional path to override prompt file
    # DefectDojo
    defectdojo_base_url: str | None = os.getenv("DEFECTDOJO_BASE_URL")
    defectdojo_api_key: str | None = os.getenv("DEFECTDOJO_API_KEY")
    defectdojo_verify_ssl: bool | str | None = os.getenv("DEFECTDOJO_VERIFY_SSL", "true")

    class Config:
        arbitrary_types_allowed = True

@lru_cache
def get_settings() -> Settings:
    # load .env lazily (only first call)
    load_dotenv(override=False)
    return Settings(
        deepseek_api_key=os.getenv("DEEPSEEK_API_KEY"),
    )
