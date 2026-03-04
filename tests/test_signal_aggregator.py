"""Tests for signal aggregator — written TDD style before implementation was finalized."""
import pytest

from threatsignal.models.schemas import PolymarketResult
from threatsignal.signal.aggregator import SignalAggregator


@pytest.fixture
def agg():
    return SignalAggregator()


def test_model_sees_more_risk(agg):
    result = agg.compute(0.35, PolymarketResult(status="found", probability=0.15))
    assert result.signal == "MODEL_SEES_MORE_RISK"
    assert result.delta > 0


def test_market_sees_more_risk(agg):
    result = agg.compute(0.10, PolymarketResult(status="found", probability=0.30))
    assert result.signal == "MARKET_SEES_MORE_RISK"
    assert result.delta < 0


def test_in_line(agg):
    result = agg.compute(0.25, PolymarketResult(status="found", probability=0.20))
    assert result.signal == "IN_LINE"


def test_market_not_available(agg):
    result = agg.compute(0.30, PolymarketResult(status="not_found"))
    assert result.signal == "MARKET_NOT_AVAILABLE"
    assert result.delta is None
    assert result.market_probability is None


def test_risk_category_low(agg):
    assert agg._categorize(0.05) == "LOW"


def test_risk_category_medium(agg):
    assert agg._categorize(0.15) == "MEDIUM"


def test_risk_category_high(agg):
    assert agg._categorize(0.35) == "HIGH"


def test_risk_category_critical(agg):
    assert agg._categorize(0.60) == "CRITICAL"
