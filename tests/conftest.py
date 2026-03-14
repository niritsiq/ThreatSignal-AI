"""Shared pytest fixtures for ThreatSignal AI tests."""

import pytest

from threatsignal.models.schemas import (
    AttackSurface,
    LLMAssessment,
    PolymarketResult,
    ServiceInfo,
    SimilarIncident,
)


@pytest.fixture
def sample_surface():
    return AttackSurface(
        ips=["12.34.56.78"],
        open_ports=[80, 443, 8443],
        services=[
            ServiceInfo(port=443, product="nginx", version="1.24.0"),
            ServiceInfo(port=8443, product="OpenSSL", version="3.0.2"),
        ],
        cve_indicators=["CVE-2022-0778"],
        hostnames=["sso.example.com"],
        org="Example Corp",
        country="US",
        attack_surface_score=5.5,
        snapshot_text="Domain example.com resolves to 1 IP hosted by Example Corp (US). "
        "Open ports: [80, 443, 8443]. CVE indicators: CVE-2022-0778.",
    )


@pytest.fixture
def sample_similar():
    return [
        SimilarIncident(
            rank=1,
            case_id="okta-2022",
            title="Okta 2022 Breach",
            year=2022,
            risk_level="high",
            similarity_score=0.89,
            key_factors=["identity provider", "SSO"],
        ),
        SimilarIncident(
            rank=2,
            case_id="lastpass-2022",
            title="LastPass 2022",
            year=2022,
            risk_level="critical",
            similarity_score=0.74,
            key_factors=["credentials", "cloud"],
        ),
    ]


@pytest.fixture
def sample_llm():
    return LLMAssessment(
        risk_level="HIGH",
        probability=0.31,
        confidence=0.72,
        main_drivers=["CVE exposure", "Identity provider target", "Similar to Okta 2022"],
        explanation="Significant exposure detected.",
        model="gpt-4o-mini",
    )


@pytest.fixture
def sample_polymarket_found():
    return PolymarketResult(
        status="found",
        market_id="0xabc",
        question="Will Example Corp be hacked?",
        probability=0.18,
        liquidity_usd=12400,
        volume_usd=45000,
    )


@pytest.fixture
def sample_polymarket_not_found():
    return PolymarketResult(status="not_found", note="No market found")
