from __future__ import annotations
import os
from dotenv import load_dotenv  # type: ignore
from functools import lru_cache
from pydantic import BaseModel
from typing import Literal

# Available LLM providers
LLMProvider = Literal["deepseek", "openrouter"]

# Provider configurations with available models
PROVIDER_CONFIGS = {
    "deepseek": {
        "name": "DeepSeek",
        "api_base": "https://api.deepseek.com/v1",
        "models": [
            {"id": "deepseek-chat", "name": "DeepSeek Chat", "description": "General purpose chat model", "category": "paid"},
            {"id": "deepseek-coder", "name": "DeepSeek Coder", "description": "Optimized for code generation", "category": "paid"},
            {"id": "deepseek-reasoner", "name": "DeepSeek Reasoner", "description": "Enhanced reasoning capabilities", "category": "paid"},
        ],
        "default_model": "deepseek-chat",
    },
    "openrouter": {
        "name": "OpenRouter",
        "api_base": "https://openrouter.ai/api/v1",
        "models": [
            # ========== FREE MODELS (27 models) ==========
            # Top-tier free models
            {"id": "x-ai/grok-4.1-fast:free", "name": "Grok 4.1 Fast", "description": "xAI's best agentic model, 2M context", "category": "free"},
            {"id": "qwen/qwen3-coder:free", "name": "Qwen3 Coder 480B", "description": "Qwen's MoE code model, 262K context", "category": "free"},
            {"id": "google/gemma-3-27b-it:free", "name": "Gemma 3 27B", "description": "Google's latest, 128K context, multimodal", "category": "free"},
            {"id": "tngtech/deepseek-r1t2-chimera:free", "name": "DeepSeek R1T2 Chimera", "description": "TNG's 671B MoE reasoning model", "category": "free"},
            {"id": "kwaipilot/kat-coder-pro:free", "name": "KAT-Coder-Pro V1", "description": "Kwai's agentic coding model, 256K context", "category": "free"},
            {"id": "tngtech/deepseek-r1t-chimera:free", "name": "DeepSeek R1T Chimera", "description": "TNG's R1+V3 merge model", "category": "free"},
            {"id": "z-ai/glm-4.5-air:free", "name": "GLM 4.5 Air", "description": "Z.AI's MoE model with thinking mode", "category": "free"},
            {"id": "nvidia/nemotron-nano-12b-v2-vl:free", "name": "Nemotron Nano 12B VL", "description": "NVIDIA's multimodal reasoning model", "category": "free"},
            # Mid-tier free models
            {"id": "google/gemma-2-9b-it:free", "name": "Gemma 2 9B", "description": "Google's efficient Gemma 2", "category": "free"},
            {"id": "meta-llama/llama-3.2-3b-instruct:free", "name": "Llama 3.2 3B", "description": "Meta's compact Llama 3.2", "category": "free"},
            {"id": "meta-llama/llama-3.1-8b-instruct:free", "name": "Llama 3.1 8B", "description": "Meta's Llama 3.1 8B", "category": "free"},
            {"id": "microsoft/phi-3-mini-128k-instruct:free", "name": "Phi-3 Mini 128K", "description": "Microsoft's compact Phi-3", "category": "free"},
            {"id": "microsoft/phi-3-medium-128k-instruct:free", "name": "Phi-3 Medium 128K", "description": "Microsoft's Phi-3 Medium", "category": "free"},
            {"id": "qwen/qwen-2-7b-instruct:free", "name": "Qwen 2 7B", "description": "Alibaba's Qwen 2 7B", "category": "free"},
            {"id": "qwen/qwen-2.5-7b-instruct:free", "name": "Qwen 2.5 7B", "description": "Alibaba's Qwen 2.5 7B", "category": "free"},
            {"id": "mistralai/mistral-7b-instruct:free", "name": "Mistral 7B", "description": "Mistral 7B Instruct", "category": "free"},
            {"id": "openchat/openchat-7b:free", "name": "OpenChat 7B", "description": "OpenChat 7B model", "category": "free"},
            {"id": "huggingfaceh4/zephyr-7b-beta:free", "name": "Zephyr 7B", "description": "HuggingFace Zephyr 7B", "category": "free"},
            {"id": "nousresearch/nous-capybara-7b:free", "name": "Nous Capybara 7B", "description": "Nous Research Capybara", "category": "free"},
            {"id": "deepseek/deepseek-r1:free", "name": "DeepSeek R1", "description": "DeepSeek's reasoning model", "category": "free"},
            {"id": "deepseek/deepseek-chat-v3-0324:free", "name": "DeepSeek V3 0324", "description": "DeepSeek Chat V3", "category": "free"},
            {"id": "moonshotai/moonlight-16b-a3b-instruct:free", "name": "Moonlight 16B", "description": "Moonshot AI's model", "category": "free"},
            {"id": "bytedance-research/ui-tars-72b:free", "name": "UI-TARS 72B", "description": "ByteDance's UI model", "category": "free"},
            {"id": "allenai/olmo-2-0325-32b-instruct:free", "name": "OLMo 2 32B", "description": "Allen AI's OLMo 2", "category": "free"},
            {"id": "featherless/qwerky-72b:free", "name": "Qwerky 72B", "description": "Featherless Qwerky model", "category": "free"},
            {"id": "open-r1/olympiccoder-32b:free", "name": "OlympicCoder 32B", "description": "Open-R1 coding model", "category": "free"},
            {"id": "rekaai/reka-flash-3:free", "name": "Reka Flash 3", "description": "Reka AI's Flash model", "category": "free"},
            
            # ========== PAID MODELS ==========
            {"id": "anthropic/claude-3.5-sonnet", "name": "Claude 3.5 Sonnet", "description": "Anthropic's latest model", "category": "paid"},
            {"id": "anthropic/claude-3-opus", "name": "Claude 3 Opus", "description": "Most powerful Claude model", "category": "paid"},
            {"id": "anthropic/claude-3-haiku", "name": "Claude 3 Haiku", "description": "Fast, affordable Claude", "category": "paid"},
            {"id": "openai/gpt-4-turbo", "name": "GPT-4 Turbo", "description": "OpenAI's GPT-4 Turbo", "category": "paid"},
            {"id": "openai/gpt-4o", "name": "GPT-4o", "description": "OpenAI's multimodal model", "category": "paid"},
            {"id": "openai/gpt-4o-mini", "name": "GPT-4o Mini", "description": "Smaller, faster GPT-4o", "category": "paid"},
            {"id": "openai/gpt-3.5-turbo", "name": "GPT-3.5 Turbo", "description": "Fast and affordable", "category": "paid"},
            {"id": "google/gemini-pro-1.5", "name": "Gemini Pro 1.5", "description": "Google's Gemini Pro", "category": "paid"},
            {"id": "google/gemini-flash-1.5", "name": "Gemini Flash 1.5", "description": "Fast Gemini model", "category": "paid"},
            {"id": "meta-llama/llama-3.1-405b-instruct", "name": "Llama 3.1 405B", "description": "Meta's largest Llama", "category": "paid"},
            {"id": "meta-llama/llama-3.1-70b-instruct", "name": "Llama 3.1 70B", "description": "Meta's Llama 70B", "category": "paid"},
            {"id": "mistralai/mistral-large", "name": "Mistral Large", "description": "Mistral's flagship model", "category": "paid"},
            {"id": "mistralai/mixtral-8x7b-instruct", "name": "Mixtral 8x7B", "description": "Mistral's MoE model", "category": "paid"},
            {"id": "qwen/qwen-2.5-72b-instruct", "name": "Qwen 2.5 72B", "description": "Alibaba's Qwen model", "category": "paid"},
            {"id": "deepseek/deepseek-chat", "name": "DeepSeek Chat (via OR)", "description": "DeepSeek via OpenRouter", "category": "paid"},
            {"id": "deepseek/deepseek-coder", "name": "DeepSeek Coder (via OR)", "description": "DeepSeek Coder via OpenRouter", "category": "paid"},
        ],
        "default_model": "x-ai/grok-4.1-fast:free",
    },
}


class Settings(BaseModel):
    # LLM Provider settings
    llm_provider: LLMProvider = "deepseek"
    selected_model: str | None = None  # If None, uses provider's default
    
    # DeepSeek settings
    deepseek_api_key: str | None = None
    deepseek_api_url: str = "https://api.deepseek.com/v1/chat/completions"
    deepseek_api_base: str | None = os.getenv("DEEPSEEK_API_BASE")  # e.g. https://api.deepseek.com/v1
    model: str = "deepseek-chat"  # Kept for backward compatibility
    
    # OpenRouter settings
    openrouter_api_key: str | None = None
    openrouter_api_base: str = "https://openrouter.ai/api/v1"
    
    searxng_base_url: str | None = os.getenv("SEARXNG_BASE_URL")  # e.g. https://searxng.example.org
    searxng_headers: dict[str, str] = {}
    environment: str = os.getenv("ENV", "dev")
    prompt_path: str | None = os.getenv("PROMPT_PATH")  # optional path to override prompt file
    
    # DefectDojo
    defectdojo_base_url: str | None = os.getenv("DEFECTDOJO_BASE_URL")
    defectdojo_api_key: str | None = os.getenv("DEFECTDOJO_API_KEY")
    defectdojo_verify_ssl: bool | str | None = os.getenv("DEFECTDOJO_VERIFY_SSL", "true")
    defectdojo_default_product_type_id: int | None = (
        int(os.getenv("DEFECTDOJO_DEFAULT_PRODUCT_TYPE_ID")) if os.getenv("DEFECTDOJO_DEFAULT_PRODUCT_TYPE_ID") else None
    )
    
    # OSINT API Keys (all optional - tools will indicate when key is missing)
    virustotal_api_key: str | None = os.getenv("VIRUSTOTAL_API_KEY")
    shodan_api_key: str | None = os.getenv("SHODAN_API_KEY")
    hunter_api_key: str | None = os.getenv("HUNTER_API_KEY")
    securitytrails_api_key: str | None = os.getenv("SECURITYTRAILS_API_KEY")
    whoisxml_api_key: str | None = os.getenv("WHOISXML_API_KEY")
    hibp_api_key: str | None = os.getenv("HIBP_API_KEY")
    wpscan_api_token: str | None = os.getenv("WPSCAN_API_TOKEN")
    
    # Agent Configuration
    agent_max_steps: int = 200  # Maximum steps for agent execution (50-500 recommended)

    class Config:
        arbitrary_types_allowed = True
    
    def get_active_api_key(self) -> str | None:
        """Get the API key for the currently selected provider."""
        if self.llm_provider == "openrouter":
            return self.openrouter_api_key
        return self.deepseek_api_key
    
    def get_active_api_base(self) -> str:
        """Get the API base URL for the currently selected provider."""
        provider_config = PROVIDER_CONFIGS.get(self.llm_provider, PROVIDER_CONFIGS["deepseek"])
        if self.llm_provider == "openrouter":
            return self.openrouter_api_base or provider_config["api_base"]
        return self.deepseek_api_base or provider_config["api_base"]
    
    def get_active_model(self) -> str:
        """Get the model ID for the currently selected provider."""
        if self.selected_model:
            return self.selected_model
        provider_config = PROVIDER_CONFIGS.get(self.llm_provider, PROVIDER_CONFIGS["deepseek"])
        return provider_config["default_model"]


# Mutable settings that can be changed at runtime
_runtime_settings: dict = {}


def update_runtime_settings(**kwargs):
    """Update runtime settings (provider, model, etc.)."""
    global _runtime_settings
    _runtime_settings.update(kwargs)
    # Clear the cached settings so next get_settings() returns updated values
    get_settings.cache_clear()


def get_runtime_settings() -> dict:
    """Get current runtime settings."""
    return _runtime_settings.copy()


@lru_cache
def get_settings() -> Settings:
    # load .env lazily (only first call)
    load_dotenv(override=False)
    
    # Build settings from environment and runtime overrides
    settings_dict = {
        "deepseek_api_key": os.getenv("DEEPSEEK_API_KEY"),
        "openrouter_api_key": os.getenv("OPENROUTER_API_KEY"),
        "llm_provider": os.getenv("LLM_PROVIDER", "deepseek"),
        "selected_model": os.getenv("SELECTED_MODEL"),
    }
    
    # Add agent_max_steps from environment if set
    env_max_steps = os.getenv("AGENT_MAX_STEPS")
    if env_max_steps:
        try:
            settings_dict["agent_max_steps"] = int(env_max_steps)
        except ValueError:
            pass  # Use default if invalid
    
    # Apply runtime overrides
    settings_dict.update(_runtime_settings)
    
    return Settings(**{k: v for k, v in settings_dict.items() if v is not None})
