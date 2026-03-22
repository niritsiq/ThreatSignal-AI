"""Tests for LLMReasoner — checks parsing, retry logic, and fallback behavior."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from openai import RateLimitError

from threatsignal.llm.reasoner import LLMReasoner
from threatsignal.models.schemas import AttackSurface


@pytest.fixture
def reasoner():
    # use_function_calling=False so tests use the simpler JSON mode path
    return LLMReasoner(api_key="test-key", model="gpt-4o-mini", use_function_calling=False)


@pytest.fixture
def surface():
    return AttackSurface(
        ips=["1.2.3.4"],
        open_ports=[443],
        cve_indicators=[],
        attack_surface_score=4.0,
        snapshot_text="Test surface",
    )


def _mock_response(payload: dict) -> MagicMock:
    """Build a fake OpenAI chat completion response."""
    msg = MagicMock()
    msg.content = json.dumps(payload)
    choice = MagicMock()
    choice.message = msg
    usage = MagicMock()
    usage.prompt_tokens = 100
    usage.completion_tokens = 50
    resp = MagicMock()
    resp.choices = [choice]
    resp.usage = usage
    return resp


VALID_PAYLOAD = {
    "risk_level": "HIGH",
    "probability": 0.42,
    "confidence": 0.80,
    "main_drivers": ["exposed RDP", "known CVE", "high-value target"],
    "explanation": "Significant exposure detected.",
}


def test_valid_response_is_parsed_correctly(reasoner, surface):
    with patch.object(reasoner.client.chat.completions, "create", return_value=_mock_response(VALID_PAYLOAD)):
        result = reasoner.assess("acme.com", surface, [], 30)
    assert result.risk_level == "HIGH"
    assert result.probability == pytest.approx(0.42)
    assert result.confidence == pytest.approx(0.80)
    assert len(result.main_drivers) == 3


def test_rate_limit_triggers_retry(reasoner, surface):
    rate_err = RateLimitError("rate limited", response=MagicMock(), body={})
    success = _mock_response(VALID_PAYLOAD)
    with patch.object(
        reasoner.client.chat.completions,
        "create",
        side_effect=[rate_err, success],
    ):
        with patch("time.sleep"):
            result = reasoner.assess("acme.com", surface, [], 30)
    assert result.risk_level == "HIGH"


def test_three_rate_limit_failures_return_fallback(reasoner, surface):
    rate_err = RateLimitError("rate limited", response=MagicMock(), body={})
    with patch.object(reasoner.client.chat.completions, "create", side_effect=[rate_err, rate_err, rate_err]):
        with patch("time.sleep"):
            result = reasoner.assess("acme.com", surface, [], 30)
    assert result.risk_level == "MEDIUM"
    assert result.confidence == pytest.approx(0.1)


def test_invalid_json_triggers_fallback(reasoner, surface):
    bad_msg = MagicMock()
    bad_msg.content = "this is not json {"
    bad_choice = MagicMock()
    bad_choice.message = bad_msg
    bad_resp = MagicMock()
    bad_resp.choices = [bad_choice]
    bad_resp.usage = MagicMock(prompt_tokens=10, completion_tokens=5)
    with patch.object(reasoner.client.chat.completions, "create", return_value=bad_resp):
        result = reasoner.assess("acme.com", surface, [], 30)
    assert "could not be completed" in result.explanation.lower()


def test_fallback_probability_is_conservative(reasoner, surface):
    """Fallback must not overstate risk — should use a low probability."""
    with patch.object(reasoner.client.chat.completions, "create", side_effect=Exception("API down")):
        result = reasoner._fallback_assessment()
    assert result.probability <= 0.15


def test_llm_reasoner_uses_azure_when_endpoint_given():
    """When azure_endpoint is set, LLMReasoner must use AzureOpenAI, not OpenAI."""
    with patch("threatsignal.llm.reasoner.AzureOpenAI") as mock_azure:
        mock_azure.return_value = MagicMock()
        LLMReasoner(
            api_key="azure-key",
            model="gpt-4o-mini",
            azure_endpoint="https://foo.openai.azure.com",
            azure_api_version="2024-10-21",
        )
        mock_azure.assert_called_once()
