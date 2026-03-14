"""Tests for EmbeddingEngine and BreachIndex.

EmbeddingEngine tests mock the OpenAI HTTP call — we test the plumbing,
not the model.

BreachIndex tests use the REAL FAISS index on disk (data/breach_index.faiss)
so the vector math, dimension handling, and similarity ranking are exercised
against actual breach embeddings — no mocking.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from threatsignal.embeddings.engine import EmbeddingEngine
from threatsignal.embeddings.index import BreachIndex

FAISS_PATH = "data/breach_index.faiss"
METADATA_PATH = "data/breach_cases.jsonl"

# A 1536-float vector — same dimensionality as text-embedding-3-small
FAKE_VECTOR = [round(0.001 * i, 4) for i in range(1536)]


# ── EmbeddingEngine ────────────────────────────────────────────────────────────


def test_embed_returns_1536_dimensions():
    """text-embedding-3-small must return exactly 1536 floats."""
    with patch("threatsignal.embeddings.engine.OpenAI") as mock_openai:
        mock_client = MagicMock()
        mock_openai.return_value = mock_client
        mock_client.embeddings.create.return_value = MagicMock(data=[MagicMock(embedding=FAKE_VECTOR)])
        engine = EmbeddingEngine(api_key="test-key")
        result = engine.embed("ransomware attack on identity provider")
        assert len(result) == 1536


def test_embed_uses_configured_model():
    """Engine must pass the configured model name to the API."""
    with patch("threatsignal.embeddings.engine.OpenAI") as mock_openai:
        mock_client = MagicMock()
        mock_openai.return_value = mock_client
        mock_client.embeddings.create.return_value = MagicMock(data=[MagicMock(embedding=FAKE_VECTOR)])
        engine = EmbeddingEngine(api_key="test-key", model="text-embedding-3-small")
        engine.embed("some breach text")
        call_kwargs = mock_client.embeddings.create.call_args[1]
        assert call_kwargs["model"] == "text-embedding-3-small"


def test_embed_batch_returns_one_vector_per_input():
    """embed_batch must return exactly as many vectors as texts given."""
    two_vectors = [FAKE_VECTOR, FAKE_VECTOR]
    with patch("threatsignal.embeddings.engine.OpenAI") as mock_openai:
        mock_client = MagicMock()
        mock_openai.return_value = mock_client
        mock_client.embeddings.create.return_value = MagicMock(data=[MagicMock(embedding=v) for v in two_vectors])
        engine = EmbeddingEngine(api_key="test-key")
        results = engine.embed_batch(["breach one", "breach two"])
        assert len(results) == 2
        assert len(results[0]) == 1536


# ── BreachIndex — uses REAL FAISS data on disk ────────────────────────────────


@pytest.fixture(scope="module")
def loaded_index():
    """Load the actual FAISS index built from real breach cases."""
    idx = BreachIndex()
    idx.load(FAISS_PATH, METADATA_PATH)
    return idx


def test_index_loads_all_cases(loaded_index):
    """Index must have at least 20 breach cases (we built it with 21)."""
    assert loaded_index.index.ntotal >= 20
    assert len(loaded_index.cases) >= 20


def test_search_returns_exactly_top_k(loaded_index):
    """search() must return exactly the number of results requested."""
    query = [0.0] * 1536
    results = loaded_index.search(query, top_k=3)
    assert len(results) == 3


def test_similarity_scores_are_in_valid_range(loaded_index):
    """All cosine similarity scores must be between 0.0 and 1.0."""
    query = [0.5] * 1536
    results = loaded_index.search(query, top_k=5)
    for r in results:
        assert 0.0 <= r.similarity_score <= 1.0, f"Score out of bounds: {r.similarity_score}"


def test_results_are_ranked_highest_first(loaded_index):
    """Results must be ordered by descending similarity score."""
    query = [0.1 * (i % 7) for i in range(1536)]
    results = loaded_index.search(query, top_k=5)
    scores = [r.similarity_score for r in results]
    assert scores == sorted(scores, reverse=True)


def test_searching_stored_vector_returns_near_perfect_score(loaded_index):
    """Searching with a vector already in the index should return similarity ≈ 1.0.

    This is the strongest proof that the index contains real data: the stored
    breach vectors were built from actual OpenAI embeddings, so querying with
    one of them should produce a near-perfect match for that case.
    """
    stored_vec = loaded_index.index.reconstruct(0)  # vector for case 0
    results = loaded_index.search(stored_vec.tolist(), top_k=1)
    assert len(results) == 1
    assert (
        results[0].similarity_score > 0.99
    ), f"Expected similarity ~1.0 for stored vector, got {results[0].similarity_score}"


def test_each_result_has_required_fields(loaded_index):
    """Every SimilarIncident must have a title, case_id, year, and risk_level."""
    query = np.random.default_rng(0).random(1536).tolist()
    results = loaded_index.search(query, top_k=3)
    for r in results:
        assert r.title, "title must not be empty"
        assert r.case_id, "case_id must not be empty"
        assert r.year > 2000, f"year looks wrong: {r.year}"
        assert r.risk_level in {"low", "medium", "high", "critical"}


def test_search_raises_if_index_not_loaded():
    """search() must raise RuntimeError if load() was never called."""
    fresh = BreachIndex()
    with pytest.raises(RuntimeError, match="not loaded"):
        fresh.search([0.0] * 1536, top_k=1)
