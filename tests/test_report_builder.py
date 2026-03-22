"""Tests for ReportBuilder — checks report assembly, UUIDs, timestamps, and file output."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.console import Console as RichConsole

from threatsignal.models.schemas import (
    AttackSurface,
    FinalSignal,
    LLMAssessment,
    PolymarketResult,
    SimilarIncident,
    TrendResult,
)
from threatsignal.report.builder import ReportBuilder


@pytest.fixture
def builder():
    return ReportBuilder()


@pytest.fixture
def sample_inputs():
    surface = AttackSurface(
        ips=["1.2.3.4"],
        open_ports=[443, 80],
        cve_indicators=["CVE-2023-1234"],
        org="Acme Corp",
        country="US",
        attack_surface_score=5.5,
        snapshot_text="Test snapshot",
    )
    similar = [
        SimilarIncident(
            rank=1,
            case_id="case-1",
            title="SolarWinds supply chain attack",
            year=2020,
            risk_level="CRITICAL",
            similarity_score=0.92,
            key_factors=["supply chain", "backdoor"],
        )
    ]
    llm = LLMAssessment(
        risk_level="HIGH",
        probability=0.35,
        confidence=0.75,
        main_drivers=["exposed RDP", "known CVE"],
        explanation="High exposure detected.",
        model="gpt-4o-mini",
    )
    polymarket = PolymarketResult(status="not_found", note="No active markets found")
    signal = FinalSignal(
        model_probability=0.35,
        market_probability=None,
        delta=None,
        signal="MARKET_NOT_AVAILABLE",
        interpretation="Model estimate only — no market data.",
        risk_category="HIGH",
    )
    return surface, similar, llm, polymarket, signal


def test_build_returns_valid_response(builder, sample_inputs):
    surface, similar, llm, polymarket, signal = sample_inputs
    response = builder.build("acme.com", 30, surface, similar, llm, polymarket, signal)
    assert response.meta.domain == "acme.com"
    assert response.meta.time_horizon_days == 30
    assert response.final_signal.risk_category == "HIGH"


def test_request_id_is_valid_uuid(builder, sample_inputs):
    surface, similar, llm, polymarket, signal = sample_inputs
    response = builder.build("acme.com", 30, surface, similar, llm, polymarket, signal)
    parsed = uuid.UUID(response.meta.request_id)
    assert str(parsed) == response.meta.request_id


def test_generated_at_is_valid_iso_timestamp(builder, sample_inputs):
    surface, similar, llm, polymarket, signal = sample_inputs
    response = builder.build("acme.com", 30, surface, similar, llm, polymarket, signal)
    parsed = datetime.fromisoformat(response.meta.generated_at)
    assert parsed.tzinfo == timezone.utc


def test_each_build_gets_unique_request_id(builder, sample_inputs):
    surface, similar, llm, polymarket, signal = sample_inputs
    r1 = builder.build("acme.com", 30, surface, similar, llm, polymarket, signal)
    r2 = builder.build("acme.com", 30, surface, similar, llm, polymarket, signal)
    assert r1.meta.request_id != r2.meta.request_id


def test_save_json_creates_file(builder, sample_inputs, tmp_path):
    surface, similar, llm, polymarket, signal = sample_inputs
    response = builder.build("acme.com", 30, surface, similar, llm, polymarket, signal)
    path = builder.save_json(response, output_dir=str(tmp_path))
    assert Path(path).exists()


def test_save_json_content_is_valid(builder, sample_inputs, tmp_path):
    surface, similar, llm, polymarket, signal = sample_inputs
    response = builder.build("acme.com", 30, surface, similar, llm, polymarket, signal)
    path = builder.save_json(response, output_dir=str(tmp_path))
    with open(path) as f:
        data = json.load(f)
    assert data["meta"]["domain"] == "acme.com"
    assert data["final_signal"]["risk_category"] == "HIGH"
    assert "attack_surface" in data
    assert "llm_assessment" in data


def _capture_cli(builder, response) -> str:
    """Helper: run print_cli and return all rendered text."""
    buf = StringIO()
    with patch("threatsignal.report.builder.Console", return_value=RichConsole(file=buf, highlight=False)):
        builder.print_cli(response)
    return buf.getvalue()


def test_print_cli_contains_domain_and_sections(builder, sample_inputs):
    surface, similar, llm, polymarket, signal = sample_inputs
    response = builder.build("acme.com", 30, surface, similar, llm, polymarket, signal)
    output = _capture_cli(builder, response)
    assert "acme.com" in output
    assert "ATTACK SURFACE" in output
    assert "SIMILAR HISTORICAL BREACHES" in output
    assert "LLM RISK ASSESSMENT" in output
    assert "POLYMARKET SIGNAL" in output
    assert "FINAL SIGNAL" in output


def test_print_cli_with_polymarket_found(builder, sample_inputs):
    surface, similar, llm, _, _ = sample_inputs
    pm_found = PolymarketResult(
        status="found",
        market_id="abc123",
        question="Will acme suffer a cyber breach in 2025?",
        probability=0.28,
        liquidity_usd=50000.0,
        volume_usd=120000.0,
        url="https://polymarket.com/event/acme-breach",
    )
    signal_with_market = FinalSignal(
        model_probability=0.35,
        market_probability=0.28,
        delta=0.07,
        signal="MODEL_SEES_MORE_RISK",
        interpretation="Model sees higher risk than market.",
        risk_category="HIGH",
    )
    response = builder.build("acme.com", 30, surface, similar, llm, pm_found, signal_with_market)
    output = _capture_cli(builder, response)
    assert "FOUND" in output
    assert "28.00%" in output


def test_print_cli_with_trend_section(builder, sample_inputs):
    surface, similar, llm, polymarket, signal = sample_inputs
    response = builder.build("acme.com", 30, surface, similar, llm, polymarket, signal)
    response.trend = TrendResult(
        direction="INCREASING",
        delta=0.12,
        current_category="HIGH",
        previous_category="MEDIUM",
        severity_changed=True,
    )
    output = _capture_cli(builder, response)
    assert "RISK TREND" in output
    assert "INCREASING" in output
    assert "severity category changed" in output.lower()
