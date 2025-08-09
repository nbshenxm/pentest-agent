import logging
from typing import Dict, Any
from abc import ABC, abstractmethod
from langchain_core.language_models import BaseLLM
from langchain_openai import ChatOpenAI
from langchain_deepseek import ChatDeepSeek

logger = logging.getLogger(__name__)

class BaseLLMProvider(ABC):
    @abstractmethod
    def create_llm(self, config: Dict[str, Any]) -> BaseLLM:
        pass

    @abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> bool:
        pass

class OpenAIProvider(BaseLLMProvider):
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return 'api_key' in config and 'model' in config

    def create_llm(self, config: Dict[str, Any]) -> BaseLLM:
        return ChatOpenAI(
            api_key=config['api_key'],
            model=config['model'],
            temperature=config.get('temperature', 0),
            max_tokens=config.get('max_tokens'),
            streaming=config.get('streaming', False),
            timeout=config.get('timeout', 30),
            max_retries=2,
        )

class DeepSeekProvider(BaseLLMProvider):
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return 'api_key' in config and 'model' in config

    def create_llm(self, config: Dict[str, Any]) -> BaseLLM:
        return ChatDeepSeek(
            api_key=config['api_key'],
            model=config['model'],
            temperature=config.get('temperature', 0),
            max_tokens=config.get('max_tokens'),
            streaming=config.get('streaming', False),
            timeout=config.get('timeout', 30),
        )

class LLMFactory:
    _providers = {
        'openai': OpenAIProvider(),
        'deepseek': DeepSeekProvider()
    }

    @classmethod
    def create_llm(cls, provider: str, config: Dict[str, Any]) -> BaseLLM:
        if provider not in cls._providers:
            raise ValueError(f"Unsupported provider: {provider}")
        return cls._providers[provider].create_llm(config)

class LLMManager:
    def __init__(self):
        self._llms = {}
        self._configs = {}

    def create_llm(self, name: str, provider: str, config: Dict[str, Any]) -> BaseLLM:
        llm = LLMFactory.create_llm(provider, config)
        self._llms[name] = llm
        self._configs[name] = {'provider': provider, 'config': config}
        return llm

    def get_llm(self, name: str):
        return self._llms.get(name)

llm_manager = LLMManager()

def create_llm_from_config(config: Dict[str, Any]) -> BaseLLM:
    provider = config.get('provider', 'openai')
    name = config.get('name', 'default')
    clean_config = {k: v for k, v in config.items() if k not in ['provider', 'name']}
    return llm_manager.create_llm(name, provider, clean_config)