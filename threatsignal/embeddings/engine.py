"""Embedding engine — supports both OpenAI and Azure OpenAI."""

from __future__ import annotations

import logging

from openai import AzureOpenAI, OpenAI

logger = logging.getLogger(__name__)


class EmbeddingEngine:
    def __init__(
        self,
        api_key: str,
        model: str = "text-embedding-3-small",
        azure_endpoint: str = "",
        azure_api_version: str = "",
    ):
        if azure_endpoint:
            self.client = AzureOpenAI(
                azure_endpoint=azure_endpoint,
                api_key=api_key,
                api_version=azure_api_version,
            )
            logger.info("EmbeddingEngine using Azure OpenAI endpoint: %s", azure_endpoint)
        else:
            self.client = OpenAI(api_key=api_key)
        self.model = model

    def embed(self, text: str) -> list[float]:
        """Embed a text string, return float vector."""
        response = self.client.embeddings.create(model=self.model, input=text)
        return response.data[0].embedding

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Embed multiple texts in one API call."""
        response = self.client.embeddings.create(model=self.model, input=texts)
        return [item.embedding for item in response.data]
