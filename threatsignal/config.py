from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    shodan_api_key: str = ""
    openai_api_key: str = ""
    polymarket_api_key: str = ""
    serp_api_key: str = ""
    log_level: str = "INFO"
    embedding_model: str = "text-embedding-3-small"
    llm_model: str = "gpt-4o-mini"
    top_k_similar: int = 3
    breach_dataset_path: str = "data/breach_cases.jsonl"
    faiss_index_path: str = "data/breach_index.faiss"

    # Azure OpenAI — leave empty to use regular OpenAI
    azure_openai_endpoint: str = ""
    azure_openai_api_key: str = ""
    azure_openai_api_version: str = "2024-10-21"
    azure_embedding_deployment: str = "text-embedding-3-small"
    azure_llm_deployment: str = "gpt-4o-mini"

    @property
    def use_azure(self) -> bool:
        return bool(self.azure_openai_endpoint)

    class Config:
        env_file = ".env"


settings = Settings()
