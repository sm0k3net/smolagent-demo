from __future__ import annotations
import os
import httpx
from app.config import get_settings

class DeepSeekChatModel:
    """Minimal DeepSeek chat model wrapper compatible with smolagents.

    Tolerates extra keyword arguments passed by smolagents (e.g. stop_sequences, top_p, max_tokens, temperature).
    Unsupported parameters are ignored gracefully so they don't raise errors.
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

    def generate(
        self,
        prompt: str,
        messages: list[dict] | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.2,
        **kwargs,
    ) -> str:
        # Accept common alternative kw names
        if "max_new_tokens" in kwargs and not kwargs.get("max_tokens"):
            max_tokens = kwargs["max_new_tokens"]
        if "temperature" in kwargs:
            temperature = kwargs["temperature"]
        stop_sequences = kwargs.get("stop_sequences") or kwargs.get("stop")
        top_p = kwargs.get("top_p")
        provided_messages = kwargs.get("messages") or messages
        payload = {
            "model": self.model,
            "messages": provided_messages or [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if stop_sequences:
            payload["stop"] = stop_sequences
        if top_p is not None:
            payload["top_p"] = top_p
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "owasp-smolagent/0.1",
        }
        try:
            with httpx.Client(timeout=60) as client:
                r = client.post(self.api_url, json=payload, headers=headers)
                r.raise_for_status()
                data = r.json()
                try:
                    return data["choices"][0]["message"]["content"].strip()
                except Exception:  # pragma: no cover
                    return str(data)
        except Exception as e:  # pragma: no cover
            return f"DeepSeek API error: {e}"

    # smolagents expects generate_response sometimes
    def generate_response(self, prompt: str, **kwargs) -> str:
        return self.generate(prompt, **kwargs)

    @property
    def model_name(self):  # type: ignore
        return self.model
