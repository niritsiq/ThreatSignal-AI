"""End-to-end pipeline test for ThreatSignal AI.

Tests the full _run_analysis() pipeline from domain input to AnalyzeResponse.

What is REAL in this test (no mocking):
  - AttackSurfaceNormalizer — parses the mock Shodan dict into AttackSurface
  - BreachIndex FAISS search — uses the actual breach_index.faiss on disk
  - SignalAggregator — computes the final risk signal from probabilities
  - ReportBuilder — assembles the AnalyzeResponse
  - RiskTrend — computes direction against previous run (None = NEW on first run)

What is MOCKED (HTTP calls to external APIs):
  - ShodanClient.query_domain — returns a realistic okta.com-shaped fixture
  - EmbeddingEngine.embed — returns a valid 1536-float vector (no API cost)
  - LLMReasoner.assess — returns a realistic LLMAssessment object
  - PolymarketClient.search — returns a Polymarket market fixture
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from threatsignal.embeddings.engine import EmbeddingEngine
from threatsignal.llm.reasoner import LLMReasoner
from threatsignal.main import _run_analysis
from threatsignal.models.schemas import LLMAssessment, PolymarketResult
from threatsignal.news.client import NewsClient, NewsSignal
from threatsignal.polymarket.client import PolymarketClient
from threatsignal.shodan_client.client import ShodanClient

# ── Fixtures — shaped like real API responses ─────────────────────────────────

# Realistic Shodan response for a company with SSO infrastructure and CVE exposure
MOCK_SHODAN = {
    "hosts": [
        {
            "ip_str": "104.94.234.32",
            "org": "Okta, Inc.",
            "country_name": "United States",
            "hostnames": ["okta.com", "login.okta.com"],
            "data": [
                {
                    "port": 443,
                    "product": "nginx",
                    "version": "1.24.0",
                    "cpe": ["cpe:/a:nginx:nginx:1.24.0"],
                    "vulns": {"CVE-2022-0778": {"cvss": 7.5}},
                },
                {
                    "port": 80,
                    "product": "nginx",
                    "version": "1.24.0",
                    "cpe": [],
                    "vulns": {},
                },
                {
                    "port": 8443,
                    "product": "OpenSSL",
                    "version": "1.1.1",
                    "cpe": ["cpe:/a:openssl:openssl:1.1.1"],
                    "vulns": {"CVE-2022-0778": {"cvss": 7.5}},
                },
            ],
        }
    ],
    "search_results": [],
}

# 1536-float vector — same shape as text-embedding-3-small output
FAKE_EMBEDDING = [round(0.001 * (i % 100), 4) for i in range(1536)]

# Realistic LLM assessment for a mid-risk identity provider
MOCK_ASSESSMENT = LLMAssessment(
    risk_level="HIGH",
    probability=0.28,
    confidence=0.74,
    main_drivers=[
        "Identity provider with high-value user credentials",
        "CVE-2022-0778 detected in OpenSSL banner",
        "Similar attack profile to Okta 2022 breach",
    ],
    explanation=(
        "The target is an identity provider with exposed SSO infrastructure. "
        "CVE-2022-0778 (OpenSSL infinite-loop DoS) is present. Combined with "
        "historical similarity to the Okta 2022 breach, risk is elevated."
    ),
    model="gpt-4o-mini",
)

# Polymarket market found for a cyber event
MOCK_POLYMARKET_FOUND = PolymarketResult(
    status="found",
    market_id="0xdeadbeef",
    question="Will Okta suffer a major security breach in 2026?",
    probability=0.22,
    liquidity_usd=54000.0,
    volume_usd=180000.0,
)

MOCK_POLYMARKET_NOT_FOUND = PolymarketResult(
    status="not_found",
    note="No cyber-incident market found for 'okta'",
)


# ── Tests ─────────────────────────────────────────────────────────────────────


MOCK_NEWS_EMPTY = NewsSignal(article_count=0, headlines=[], risk_boost=0.0)


def run_pipeline(polymarket_result=None):
    """Helper: run the full pipeline with mocked external calls."""
    pm = polymarket_result or MOCK_POLYMARKET_NOT_FOUND
    with patch.object(ShodanClient, "query_domain", return_value=MOCK_SHODAN), patch.object(
        EmbeddingEngine, "embed", return_value=FAKE_EMBEDDING
    ), patch.object(LLMReasoner, "assess", return_value=MOCK_ASSESSMENT), patch.object(
        PolymarketClient, "search", return_value=pm
    ), patch.object(NewsClient, "search", return_value=MOCK_NEWS_EMPTY):
        return asyncio.run(_run_analysis("okta.com", 30))


def test_pipeline_returns_valid_response():
    """Full pipeline must complete without error and return AnalyzeResponse."""
    from threatsignal.models.schemas import AnalyzeResponse

    result = run_pipeline()
    assert isinstance(result, AnalyzeResponse)


def test_attack_surface_is_populated_from_shodan():
    """Normalizer must parse the mock Shodan dict into a real AttackSurface."""
    result = run_pipeline()
    surface = result.attack_surface
    assert "104.94.234.32" in surface.ips
    assert 443 in surface.open_ports
    assert "CVE-2022-0778" in surface.cve_indicators
    assert surface.org == "Okta, Inc."
    assert surface.attack_surface_score > 0


def test_similar_incidents_come_from_real_faiss_index():
    """FAISS search must return real breach cases from the index on disk."""
    result = run_pipeline()
    incidents = result.similar_incidents
    assert len(incidents) == 3  # top_k=3 by default
    for inc in incidents:
        assert inc.title, "Each incident must have a title"
        assert 0.0 <= inc.similarity_score <= 1.0
        assert inc.year > 2000


def test_llm_assessment_is_passed_through():
    """LLM assessment fields must appear unchanged in the response."""
    result = run_pipeline()
    assert result.llm_assessment.probability == pytest.approx(0.28)
    assert result.llm_assessment.risk_level == "HIGH"
    assert len(result.llm_assessment.main_drivers) == 3


def test_signal_computed_when_market_not_available():
    """Signal aggregator must return MARKET_NOT_AVAILABLE when no Polymarket data."""
    result = run_pipeline(polymarket_result=MOCK_POLYMARKET_NOT_FOUND)
    assert result.final_signal.signal == "MARKET_NOT_AVAILABLE"
    assert result.final_signal.model_probability == pytest.approx(0.28)


def test_signal_computed_when_market_found():
    """When a Polymarket market exists, signal and delta must be computed.

    Model=0.28, Market=0.22 → delta=0.06, within ±10pp → IN_LINE.
    """
    result = run_pipeline(polymarket_result=MOCK_POLYMARKET_FOUND)
    sig = result.final_signal
    assert sig.market_probability == pytest.approx(0.22)
    assert sig.delta == pytest.approx(0.06)
    # Delta 0.06 is within ±0.10 threshold → both signals are aligned
    assert sig.signal == "IN_LINE"


def test_risk_trend_is_new_on_first_run(tmp_path, monkeypatch):
    """First analysis of a domain should produce direction=NEW (no prior report)."""
    # Point _load_previous_probability at an empty temp directory
    monkeypatch.setattr(
        "threatsignal.main._load_previous_probability",
        lambda domain, reports_dir="reports": None,
    )
    result = run_pipeline()
    assert result.trend is not None
    assert result.trend.direction == "NEW"
    assert result.trend.delta is None


def test_response_meta_has_correct_domain_and_horizon():
    """Report metadata must reflect the domain and time horizon passed in."""
    result = run_pipeline()
    assert result.meta.domain == "okta.com"
    assert result.meta.time_horizon_days == 30
    assert result.meta.request_id  # non-empty UUID
    assert result.meta.generated_at  # non-empty ISO timestamp


def test_snapshot_text_is_embedded_correctly():
    """EmbeddingEngine.embed must be called with the attack surface snapshot."""
    with patch.object(ShodanClient, "query_domain", return_value=MOCK_SHODAN), patch.object(
        EmbeddingEngine, "embed", return_value=FAKE_EMBEDDING
    ) as mock_embed, patch.object(LLMReasoner, "assess", return_value=MOCK_ASSESSMENT), patch.object(
        PolymarketClient, "search", return_value=MOCK_POLYMARKET_NOT_FOUND
    ), patch.object(NewsClient, "search", return_value=MOCK_NEWS_EMPTY):
        asyncio.run(_run_analysis("okta.com", 30))
    # embed was called once with the snapshot text
    mock_embed.assert_called_once()
    call_arg = mock_embed.call_args[0][0]
    assert "okta.com" in call_arg.lower() or "okta" in call_arg.lower()
