"""TDD: NewsClient tests — written BEFORE the implementation exists.

NewsClient queries SerpAPI Google News for recent cyber-related headlines
about a target company and returns a risk boost signal.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from threatsignal.news.client import NewsClient

SERP_CYBER_RESULTS = [
    {
        "title": "Okta suffers major data breach exposing customer data",
        "date": "2 days ago",
        "source": {"name": "TechCrunch"},
    },
    {"title": "Okta hackers accessed source code repository", "date": "5 days ago", "source": {"name": "Wired"}},
    {
        "title": "Okta confirms third-party breach affecting support system",
        "date": "1 week ago",
        "source": {"name": "BleepingComputer"},
    },
]


def _mock_serp(results: list) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"news_results": results}
    return resp


# ── Basic search ──────────────────────────────────────────────────────────────


def test_search_returns_news_signal():
    """search() must return a NewsSignal object, never raise."""
    with patch("httpx.get", return_value=_mock_serp(SERP_CYBER_RESULTS)):
        result = NewsClient(api_key="test-key").search("okta.com")
    assert result is not None


def test_article_count_matches_results():
    """article_count must equal the number of results returned by SerpAPI."""
    with patch("httpx.get", return_value=_mock_serp(SERP_CYBER_RESULTS)):
        result = NewsClient(api_key="test-key").search("okta.com")
    assert result.article_count == 3


def test_headlines_captured():
    """headlines must contain the article titles from SerpAPI."""
    with patch("httpx.get", return_value=_mock_serp(SERP_CYBER_RESULTS)):
        result = NewsClient(api_key="test-key").search("okta.com")
    assert any("Okta" in h for h in result.headlines)


def test_zero_articles_gives_zero_boost():
    """No news articles must result in risk_boost = 0.0."""
    with patch("httpx.get", return_value=_mock_serp([])):
        result = NewsClient(api_key="test-key").search("okta.com")
    assert result.risk_boost == 0.0


def test_one_to_two_articles_gives_small_boost():
    """1–2 articles must give a small boost (0.05)."""
    with patch("httpx.get", return_value=_mock_serp(SERP_CYBER_RESULTS[:1])):
        result = NewsClient(api_key="test-key").search("okta.com")
    assert result.risk_boost == pytest.approx(0.05)


def test_three_to_five_articles_gives_medium_boost():
    """3–5 articles must give a medium boost (0.10)."""
    with patch("httpx.get", return_value=_mock_serp(SERP_CYBER_RESULTS)):
        result = NewsClient(api_key="test-key").search("okta.com")
    assert result.risk_boost == pytest.approx(0.10)


def test_six_plus_articles_gives_large_boost():
    """6+ articles must give the maximum boost (0.15)."""
    many = SERP_CYBER_RESULTS * 3  # 9 articles
    with patch("httpx.get", return_value=_mock_serp(many)):
        result = NewsClient(api_key="test-key").search("okta.com")
    assert result.risk_boost == pytest.approx(0.15)


# ── Error handling ────────────────────────────────────────────────────────────


def test_api_timeout_returns_empty_signal():
    """Timeout must return a safe zero-boost signal, not raise."""
    import httpx

    with patch("httpx.get", side_effect=httpx.TimeoutException("timeout")):
        result = NewsClient(api_key="test-key").search("okta.com")
    assert result.risk_boost == 0.0
    assert result.article_count == 0


def test_api_error_returns_empty_signal():
    """Any API error must return a safe zero-boost signal, not raise."""
    with patch("httpx.get", side_effect=Exception("connection refused")):
        result = NewsClient(api_key="test-key").search("okta.com")
    assert result.risk_boost == 0.0


def test_missing_news_results_key_handled():
    """If SerpAPI returns no news_results key, must not crash."""
    resp = MagicMock()
    resp.json.return_value = {}  # no news_results key
    with patch("httpx.get", return_value=resp):
        result = NewsClient(api_key="test-key").search("okta.com")
    assert result.article_count == 0
