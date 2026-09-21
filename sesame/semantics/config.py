from pydantic import BaseModel, Field

from sesame.bootstrap import Settings


class DeepseekLLMConfig(BaseModel):
    api_base: str = ""
    api_key: str = ""
    model: str = "DeepseekV4PRO"
    temperature: float = 0.0
    thinking: bool = True


class SemanticRuntimeConfig(BaseModel):
    llm: DeepseekLLMConfig
    max_context_chars: int = 8000


def build_semantic_runtime_config(settings: Settings) -> SemanticRuntimeConfig:
    return SemanticRuntimeConfig(
        llm=DeepseekLLMConfig(
            api_base=settings.deepseek_api_base,
            api_key=settings.deepseek_api_key,
            model=settings.deepseek_model,
            temperature=settings.deepseek_temperature,
            thinking=settings.deepseek_thinking,
        ),
        max_context_chars=settings.max_context_chars,
    )

