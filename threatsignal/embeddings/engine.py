"""Embedding engine using OpenAI text-embedding-3-small."""
from __future__ import annotations

import logging

from openai import OpenAI

logger = logging.getLogger(__name__)


class EmbeddingEngine:
    def __init__(self, api_key: str, model: str = "text-embedding-3-small"):
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
