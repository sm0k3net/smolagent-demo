from __future__ import annotations
import os
import httpx
from app.config import get_settings

class DeepSeekChatModel:
    """Minimal DeepSeek chat model wrapper.

    Designed to satisfy smolagents CodeAgent expectations:
    - expose generate_response(prompt: str, **kwargs) -> str
    - optionally callable (__call__) for convenience
    - model_name property for logging / introspection
    """
    def __init__(self, model: str | None = None):
        settings = get_settings()
        self.model = model or settings.model
        self.api_key = settings.deepseek_api_key or os.getenv("DEEPSEEK_API_KEY")
        self.api_url = settings.deepseek_api_url
        if not self.api_key:
            raise ValueError("DEEPSEEK_API_KEY not provided")

    def __call__(self, prompt: str, **kwargs) -> str:  # fallback single-turn
        return self.generate(prompt, **kwargs)

    def generate(self, prompt: str, messages: list[dict] | None = None, max_tokens: int = 1024, temperature: float = 0.2) -> str:
        payload = {
            "model": self.model,
            "messages": messages or [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        with httpx.Client(timeout=60) as client:
            r = client.post(self.api_url, json=payload, headers=headers)
            r.raise_for_status()
            data = r.json()
            # Attempt to extract content (DeepSeek assumed OpenAI-like)
            try:
                return data["choices"][0]["message"]["content"].strip()
            except Exception:  # pragma: no cover
                return str(data)

    # smolagents expects generate_response sometimes
    def generate_response(self, prompt: str, **kwargs) -> str:
        return self.generate(prompt, **kwargs)

    @property
    def model_name(self):  # type: ignore
        return self.model
