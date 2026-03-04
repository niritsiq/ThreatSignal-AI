"""FAISS index wrapper for breach case similarity search."""
from __future__ import annotations

import json
import logging

import faiss
import numpy as np

from threatsignal.models.schemas import SimilarIncident

logger = logging.getLogger(__name__)


class BreachIndex:
    def __init__(self):
        self.index: faiss.Index | None = None
        self.cases: list[dict] = []

    def load(self, faiss_path: str, metadata_path: str):
        """Load pre-built FAISS index and breach metadata."""
        self.index = faiss.read_index(faiss_path)
        with open(metadata_path, "r", encoding="utf-8") as f:
            self.cases = [json.loads(line) for line in f if line.strip()]
        logger.info(f"Loaded breach index: {self.index.ntotal} vectors, {len(self.cases)} cases")

    def search(self, query_vector: list[float], top_k: int = 3) -> list[SimilarIncident]:
        """Find top-k most similar historical breach cases."""
        if self.index is None:
            raise RuntimeError("Index not loaded. Call load() first.")

        vec = np.array([query_vector], dtype="float32")
        faiss.normalize_L2(vec)
        scores, indices = self.index.search(vec, top_k)

        results: list[SimilarIncident] = []
        for rank, (score, idx) in enumerate(zip(scores[0], indices[0]), start=1):
            if idx < 0 or idx >= len(self.cases):
                continue
            case = self.cases[idx]
            results.append(SimilarIncident(
                rank=rank,
                case_id=case.get("case_id", f"case_{idx}"),
                title=case.get("title", "Unknown"),
                year=case.get("year", 0),
                risk_level=case.get("risk_level", "unknown"),
                similarity_score=round(float(score), 4),
                key_factors=case.get("key_factors", []),
            ))
        return results
