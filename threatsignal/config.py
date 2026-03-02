from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    shodan_api_key: str = ""
    openai_api_key: str = ""
    polymarket_api_key: str = ""
    log_level: str = "INFO"
    embedding_model: str = "text-embedding-3-small"
    llm_model: str = "gpt-4o-mini"
    top_k_similar: int = 3
    breach_dataset_path: str = "data/breach_cases.jsonl"
    faiss_index_path: str = "data/breach_index.faiss"

    class Config:
        env_file = ".env"


settings = Settings()
