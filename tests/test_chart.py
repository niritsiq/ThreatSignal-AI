"""TDD: RiskChart tests — written BEFORE the implementation exists.

RiskChart generates a scatter plot PNG showing all 21 historical breach cases
on an Exposure vs Danger grid, with the current domain marked as a gold star.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from threatsignal.models.schemas import (
    AnalyzeResponse,
    AttackSurface,
    FinalSignal,
    LLMAssessment,
    PolymarketResult,
    ReportMeta,
    SimilarIncident,
    TrendResult,
)
from threatsignal.report.chart import RiskChart


@pytest.fixture
def sample_response():
    return AnalyzeResponse(
        meta=ReportMeta(
            request_id="test-id",
            domain="okta.com",
            time_horizon_days=30,
            generated_at="2026-03-24T00:00:00+00:00",
        ),
        attack_surface=AttackSurface(
            ips=["1.2.3.4"],
            open_ports=[80, 443],
            cve_indicators=["CVE-2022-0778"],
            org="Okta Inc",
            country="US",
            attack_surface_score=4.5,
            snapshot_text="Test snapshot",
        ),
        similar_incidents=[
            SimilarIncident(
                rank=1,
                case_id="okta-2022",
                title="Okta 2022 Support System Breach",
                year=2022,
                risk_level="high",
                similarity_score=0.41,
                key_factors=["identity provider", "LAPSUS$", "support system"],
            ),
            SimilarIncident(
                rank=2,
                case_id="capital-one-2019",
                title="Capital One 2019 Cloud Breach",
                year=2019,
                risk_level="high",
                similarity_score=0.34,
                key_factors=["cloud", "misconfiguration", "AWS"],
            ),
            SimilarIncident(
                rank=3,
                case_id="log4shell-2021",
                title="Log4Shell Mass Exploitation",
                year=2021,
                risk_level="critical",
                similarity_score=0.33,
                key_factors=["zero-day", "Log4j", "RCE"],
            ),
        ],
        llm_assessment=LLMAssessment(
            risk_level="MEDIUM",
            probability=0.28,
            confidence=0.75,
            main_drivers=["CVE exposure", "identity provider", "historical breaches"],
            explanation="Moderate risk based on attack surface and historical similarity.",
            model="gpt-4o-mini",
        ),
        polymarket=PolymarketResult(status="not_found", note="No active market"),
        final_signal=FinalSignal(
            model_probability=0.28,
            market_probability=None,
            delta=None,
            signal="MARKET_NOT_AVAILABLE",
            interpretation="Model-only estimate.",
            risk_category="MEDIUM",
        ),
        trend=TrendResult(direction="NEW", current_category="MEDIUM"),
    )


# ── File output ───────────────────────────────────────────────────────────────


def test_generate_creates_png_file(sample_response, tmp_path):
    """generate() must save a PNG file to the given output directory."""
    chart = RiskChart()
    path = chart.generate(sample_response, output_dir=str(tmp_path))
    assert Path(path).exists()
    assert path.endswith(".png")


def test_png_filename_contains_domain(sample_response, tmp_path):
    """The chart filename must include the domain name."""
    path = RiskChart().generate(sample_response, output_dir=str(tmp_path))
    assert "okta.com" in Path(path).name


def test_generate_creates_output_dir_if_missing(sample_response, tmp_path):
    """generate() must create the output directory if it does not exist."""
    out = str(tmp_path / "new_subdir" / "charts")
    path = RiskChart().generate(sample_response, output_dir=out)
    assert Path(path).exists()


# ── Data preparation ──────────────────────────────────────────────────────────


def test_breach_points_returns_list_of_tuples(sample_response):
    """_breach_points() must return one (x, y, label, risk_level) tuple per incident."""
    chart = RiskChart()
    points = chart._breach_points(sample_response.similar_incidents)
    assert len(points) == 3
    for x, y, label, risk in points:
        assert isinstance(x, float)
        assert isinstance(y, float)
        assert isinstance(label, str)
        assert risk in {"low", "medium", "high", "critical"}


def test_danger_score_maps_risk_levels():
    """_danger_score() must map risk_level strings to probability floats."""
    chart = RiskChart()
    assert chart._danger_score("low") == pytest.approx(0.10)
    assert chart._danger_score("medium") == pytest.approx(0.30)
    assert chart._danger_score("high") == pytest.approx(0.55)
    assert chart._danger_score("critical") == pytest.approx(0.80)


def test_exposure_score_increases_with_more_factors():
    """More key_factors must produce a higher exposure score."""
    chart = RiskChart()
    few = chart._exposure_score("high", ["one"])
    many = chart._exposure_score("high", ["one", "two", "three", "four", "five"])
    assert many > few


def test_exposure_score_bounded_0_to_10():
    """Exposure score must always stay within [0, 10]."""
    chart = RiskChart()
    factors = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]
    score = chart._exposure_score("critical", factors)
    assert 0.0 <= score <= 10.0


def test_current_domain_uses_real_scores(sample_response):
    """Current domain X must use attack_surface_score, Y must use llm probability."""
    chart = RiskChart()
    x, y = chart._current_point(sample_response)
    assert x == pytest.approx(sample_response.attack_surface.attack_surface_score)
    assert y == pytest.approx(sample_response.llm_assessment.probability)
