"""TDD: risk trend tests — written BEFORE the implementation exists."""

import pytest

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
