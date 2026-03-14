"""Tests for PolymarketClient with mocked httpx responses."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from threatsignal.polymarket.client import PolymarketClient


@pytest.fixture
def client():
    return PolymarketClient()


def _make_response(markets: list, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = markets
    resp.raise_for_status = MagicMock()
    return resp


CYBER_MARKET = {
    "conditionId": "abc123",
    "question": "will okta suffer a cyber breach in 2025?",
    "outcomePrices": ["0.25", "0.75"],
    "liquidity": "50000",
    "volume": "120000",
    "slug": "okta-breach-2025",
}


def test_finds_matching_cyber_market(client):
    with patch("httpx.Client") as mock_cls:
        mock_cls.return_value.__enter__.return_value.get.return_value = _make_response([CYBER_MARKET])
        result = client.search("okta.com")
    assert result.status == "found"
    assert result.probability == pytest.approx(0.25)
    assert "okta" in result.question.lower()


def test_non_cyber_markets_are_filtered_out(client):
    non_cyber = {
        "conditionId": "xyz",
        "question": "will okta revenue exceed $1B in 2025?",
        "outcomePrices": ["0.60"],
        "liquidity": "10000",
        "volume": "5000",
        "slug": "okta-revenue-2025",
    }
    with patch("httpx.Client") as mock_cls:
        mock_cls.return_value.__enter__.return_value.get.return_value = _make_response([non_cyber])
        result = client.search("okta.com")
    assert result.status == "not_found"


def test_empty_results_return_not_found(client):
    with patch("httpx.Client") as mock_cls:
        mock_cls.return_value.__enter__.return_value.get.return_value = _make_response([])
        result = client.search("unknown.com")
    assert result.status == "not_found"


def test_api_timeout_returns_error(client):
    import httpx

    with patch("httpx.Client") as mock_cls:
        mock_cls.return_value.__enter__.return_value.get.side_effect = httpx.TimeoutException("timeout")
        result = client.search("okta.com")
    assert result.status == "error"
    assert "timeout" in result.note.lower()


def test_api_error_returns_error_status(client):
    with patch("httpx.Client") as mock_cls:
        mock_cls.return_value.__enter__.return_value.get.side_effect = Exception("connection refused")
        result = client.search("okta.com")
    assert result.status == "error"


def test_probability_parsed_from_outcome_prices(client):
    market = {**CYBER_MARKET, "outcomePrices": ["0.72", "0.28"]}
    with patch("httpx.Client") as mock_cls:
        mock_cls.return_value.__enter__.return_value.get.return_value = _make_response([market])
        result = client.search("okta.com")
    assert result.probability == pytest.approx(0.72)
