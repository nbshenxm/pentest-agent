import os
import logging
import yaml
from typing import Dict, Any, Optional
from utils.llm_factory import llm_manager, create_llm_from_config

logger = logging.getLogger(__name__)

class ModelManager:
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), 'configs', 'config.yaml')
        self.config_path = config_path
        self.config = self._load_config()
        self.initialized_models = {}

    def _load_config(self) -> Dict[str, Any]:
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            raise

    def _process_environment_variables(self, config: Dict[str, Any]) -> Dict[str, Any]:
        processed = {}
        for key, value in config.items():
            if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                env_var = value[2:-1]
                env_val = os.getenv(env_var)
                if env_val is None:
                    logger.warning(f"Env var {env_var} not found")
                    env_val = ""
                processed[key] = env_val
            else:
                processed[key] = value
        return processed

    def get_model(self, model_name: str = "openai"):
        if model_name in self.initialized_models:
            return self.initialized_models[model_name]

        model_cfgs = self.config.get("models", {})
        if model_name not in model_cfgs:
            raise ValueError(f"Model '{model_name}' not found in config")

        cfg = self._process_environment_variables(model_cfgs[model_name])
        cfg['name'] = model_name
        llm = create_llm_from_config(cfg)
        self.initialized_models[model_name] = llm
        return llm

    def get_runtime_model(self, agent_type: str) -> str:
        runtime = self.config.get("runtime", {})
        return runtime.get(agent_type, {}).get("model", "default")

model_manager = ModelManager()

def get_model(model_name: str = "default"):
    try:
        return model_manager.get_model(model_name)
    except Exception as e:
        logger.error(f"Failed to load model '{model_name}': {e}")
        return None

def get_agent_model(agent_type: str):
    return model_manager.get_model(model_manager.get_runtime_model(agent_type))