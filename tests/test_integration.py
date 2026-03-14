"""Integration tests — call real external APIs.

These tests hit live Shodan, OpenAI, and Polymarket endpoints.
They require valid API keys in .env and cost a small amount per run.

Run with:
    pytest -m integration -v

Skip in normal CI (they run too slow and cost money):
    pytest -m "not integration"   ← default pytest run ignores these
"""

from __future__ import annotations

import asyncio
import os

import pytest
from dotenv import load_dotenv

load_dotenv()

SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")
OPENAI_KEY = os.getenv("OPENAI_API_KEY", "")

# Skip all tests in this file if API keys are missing
pytestmark = pytest.mark.integration


# ── Shodan ────────────────────────────────────────────────────────────────────


@pytest.mark.skipif(not SHODAN_KEY, reason="SHODAN_API_KEY not set")
def test_shodan_returns_real_host_data():
    """Shodan must resolve example.com and return at least one host with open ports."""
    from threatsignal.shodan_client.client import ShodanClient

    client = ShodanClient(SHODAN_KEY)
    result = client.query_domain("example.com")

    assert isinstance(result, dict)
    assert "hosts" in result
    assert "search_results" in result
    # example.com is always resolvable and Shodan has data on it
    assert len(result["hosts"]) > 0, "Expected at least one host for example.com"
    host = result["hosts"][0]
    assert "ip_str" in host


@pytest.mark.skipif(not SHODAN_KEY, reason="SHODAN_API_KEY not set")
def test_shodan_normalizer_produces_valid_surface():
    """Normalizer must produce a valid AttackSurface from real Shodan data."""
    from threatsignal.shodan_client.client import ShodanClient
    from threatsignal.shodan_client.normalizer import AttackSurfaceNormalizer

    raw = ShodanClient(SHODAN_KEY).query_domain("example.com")
    surface = AttackSurfaceNormalizer().parse(raw, "example.com")

    assert len(surface.ips) > 0
    assert len(surface.open_ports) > 0
    assert surface.attack_surface_score >= 0.0
    assert surface.snapshot_text  # must not be empty
    assert "example.com" in surface.snapshot_text


# ── OpenAI Embeddings ─────────────────────────────────────────────────────────


@pytest.mark.skipif(not OPENAI_KEY, reason="OPENAI_API_KEY not set")
def test_openai_embedding_returns_1536_floats():
    """Real OpenAI embed call must return exactly 1536 dimensions."""
    from threatsignal.embeddings.engine import EmbeddingEngine

    engine = EmbeddingEngine(api_key=OPENAI_KEY, model="text-embedding-3-small")
    vec = engine.embed("Ransomware attack on cloud identity provider with SSO exposure.")

    assert isinstance(vec, list)
    assert len(vec) == 1536
    assert all(isinstance(v, float) for v in vec)


@pytest.mark.skipif(not OPENAI_KEY, reason="OPENAI_API_KEY not set")
def test_faiss_search_with_real_embedding():
    """Embedding a real text and searching the FAISS index must return 3 valid incidents."""
    from threatsignal.embeddings.engine import EmbeddingEngine
    from threatsignal.embeddings.index import BreachIndex

    engine = EmbeddingEngine(api_key=OPENAI_KEY, model="text-embedding-3-small")
    vec = engine.embed("Identity provider breach with stolen admin credentials and SSO access.")

    index = BreachIndex()
    index.load("data/breach_index.faiss", "data/breach_cases.jsonl")
    results = index.search(vec, top_k=3)

    assert len(results) == 3
    for r in results:
        assert r.title
        assert 0.0 <= r.similarity_score <= 1.0


# ── LLM Reasoner ─────────────────────────────────────────────────────────────


@pytest.mark.skipif(not OPENAI_KEY, reason="OPENAI_API_KEY not set")
def test_llm_returns_valid_risk_assessment():
    """Real GPT function-calling response must produce a valid LLMAssessment."""
    from threatsignal.llm.reasoner import LLMReasoner
    from threatsignal.models.schemas import AttackSurface, ServiceInfo

    llm = LLMReasoner(api_key=OPENAI_KEY, model="gpt-4o-mini")

    surface = AttackSurface(
        ips=["93.184.216.34"],
        open_ports=[80, 443],
        services=[ServiceInfo(port=443, product="nginx", version="1.24.0")],
        cve_indicators=["CVE-2022-0778"],
        org="Example Corp",
        country="United States",
        attack_surface_score=3.5,
        snapshot_text=(
            "Domain example.com resolves to 1 IP hosted by Example Corp (US). "
            "Open ports: [80, 443]. CVE indicators: CVE-2022-0778. "
            "Attack surface score: 3.5/10."
        ),
    )

    assessment = llm.assess(
        domain="example.com",
        surface=surface,
        similar=[],
        horizon_days=30,
    )

    assert assessment.risk_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert 0.0 <= assessment.probability <= 1.0
    assert 0.0 <= assessment.confidence <= 1.0
    assert len(assessment.main_drivers) > 0
    assert assessment.explanation


# ── Polymarket ────────────────────────────────────────────────────────────────


def test_polymarket_search_does_not_crash():
    """Polymarket search must return a valid result (found or not_found) for any domain."""
    from threatsignal.polymarket.client import PolymarketClient

    client = PolymarketClient()
    result = client.search("example.com")

    assert result.status in {"found", "not_found", "error"}


def test_polymarket_search_for_known_company():
    """Searching for a well-known company should not crash and return a structured result."""
    from threatsignal.polymarket.client import PolymarketClient

    result = PolymarketClient().search("microsoft.com")

    assert result.status in {"found", "not_found", "error"}
    if result.status == "found":
        assert result.question
        assert 0.0 <= result.probability <= 1.0
        assert result.market_id


# ── Full pipeline ─────────────────────────────────────────────────────────────


@pytest.mark.skipif(not SHODAN_KEY or not OPENAI_KEY, reason="API keys not set")
def test_full_pipeline_live_end_to_end():
    """Run the complete pipeline against example.com with all real APIs.

    Validates:
    - Every field in AnalyzeResponse is populated
    - LLM probability is in [0, 1]
    - FAISS found 3 similar incidents
    - RiskTrend direction is set
    - Report can be serialized to JSON
    """
    from threatsignal.main import _run_analysis

    result = asyncio.run(_run_analysis("example.com", 30))

    # Meta
    assert result.meta.domain == "example.com"
    assert result.meta.request_id

    # Attack surface — real Shodan data
    assert len(result.attack_surface.ips) > 0
    assert len(result.attack_surface.open_ports) > 0
    assert result.attack_surface.snapshot_text

    # Similar incidents — real FAISS search on real embedding
    assert len(result.similar_incidents) == 3
    for inc in result.similar_incidents:
        assert inc.title
        assert 0.0 <= inc.similarity_score <= 1.0

    # LLM — real GPT response
    assert result.llm_assessment.risk_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert 0.0 <= result.llm_assessment.probability <= 1.0
    assert result.llm_assessment.explanation

    # Signal
    assert result.final_signal.signal in {
        "MODEL_SEES_MORE_RISK",
        "MARKET_SEES_MORE_RISK",
        "IN_LINE",
        "MARKET_NOT_AVAILABLE",
    }

    # Trend — first run = NEW, subsequent runs = INCREASING/DECREASING/STABLE
    assert result.trend is not None
    assert result.trend.direction in {"NEW", "INCREASING", "DECREASING", "STABLE"}

    # Serializable to JSON
    import json

    json_str = json.dumps(result.model_dump())
    assert len(json_str) > 100
