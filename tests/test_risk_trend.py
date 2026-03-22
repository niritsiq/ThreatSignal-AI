"""TDD: risk trend tests — written BEFORE the implementation exists."""

import pytest

from threatsignal.models.schemas import TrendResult
from threatsignal.signal.trend import RiskTrend


@pytest.fixture
def trend():
    return RiskTrend()


def test_increasing_risk(trend):
    result = trend.compare(current_prob=0.40, previous_prob=0.15)
    assert result["direction"] == "INCREASING"
    assert result["delta"] == pytest.approx(0.25, abs=0.001)


def test_decreasing_risk(trend):
    result = trend.compare(current_prob=0.10, previous_prob=0.35)
    assert result["direction"] == "DECREASING"
    assert result["delta"] == pytest.approx(-0.25, abs=0.001)


def test_stable_risk(trend):
    result = trend.compare(current_prob=0.20, previous_prob=0.22)
    assert result["direction"] == "STABLE"


def test_new_assessment_no_previous(trend):
    result = trend.compare(current_prob=0.30, previous_prob=None)
    assert result["direction"] == "NEW"
    assert result["delta"] is None


def test_severity_change_upgrade(trend):
    result = trend.compare(current_prob=0.55, previous_prob=0.20)
    assert result["severity_changed"] is True
    assert result["previous_category"] == "MEDIUM"
    assert result["current_category"] == "CRITICAL"


def test_severity_change_same_category(trend):
    result = trend.compare(current_prob=0.12, previous_prob=0.18)
    assert result["severity_changed"] is False


def test_format_summary_new():
    t = TrendResult(direction="NEW", current_category="HIGH")
    summary = t.format_summary()
    assert "First assessment" in summary
    assert "HIGH" in summary


def test_format_summary_increasing():
    t = TrendResult(direction="INCREASING", delta=0.15, current_category="HIGH", previous_category="MEDIUM")
    summary = t.format_summary()
    assert "↑" in summary
    assert "INCREASING" in summary


def test_format_summary_severity_change():
    t = TrendResult(
        direction="INCREASING",
        delta=0.35,
        current_category="CRITICAL",
        previous_category="MEDIUM",
        severity_changed=True,
    )
    summary = t.format_summary()
    assert "severity changed" in summary
    assert "MEDIUM" in summary
    assert "CRITICAL" in summary
