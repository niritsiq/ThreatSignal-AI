"""Tests for LLM prompt builder — checks all required fields appear in the output."""

from __future__ import annotations

from threatsignal.llm.prompts import build_user_prompt


def test_prompt_contains_domain():
    prompt = build_user_prompt(
        domain="okta.com",
        horizon_days=30,
        snapshot_text="Some snapshot",
        attack_surface_score=5.0,
        open_ports=[443],
        cve_indicators=[],
        similar_incidents=[],
    )
    assert "okta.com" in prompt


def test_prompt_contains_horizon_days():
    prompt = build_user_prompt(
        domain="okta.com",
        horizon_days=60,
        snapshot_text="",
        attack_surface_score=3.0,
        open_ports=[],
        cve_indicators=[],
        similar_incidents=[],
    )
    assert "60" in prompt


def test_prompt_contains_attack_surface_score():
    prompt = build_user_prompt(
        domain="example.com",
        horizon_days=30,
        snapshot_text="",
        attack_surface_score=7.5,
        open_ports=[],
        cve_indicators=[],
        similar_incidents=[],
    )
    assert "7.5" in prompt


def test_prompt_contains_cve_indicators():
    prompt = build_user_prompt(
        domain="target.com",
        horizon_days=30,
        snapshot_text="",
        attack_surface_score=6.0,
        open_ports=[],
        cve_indicators=["CVE-2023-1234", "CVE-2022-9999"],
        similar_incidents=[],
    )
    assert "CVE-2023-1234" in prompt


def test_prompt_formats_similar_incidents():
    incidents = [
        {
            "title": "SolarWinds breach",
            "year": 2020,
            "risk_level": "CRITICAL",
            "similarity_score": 0.91,
            "key_factors": ["supply chain", "nation state"],
        }
    ]
    prompt = build_user_prompt(
        domain="target.com",
        horizon_days=30,
        snapshot_text="",
        attack_surface_score=5.0,
        open_ports=[],
        cve_indicators=[],
        similar_incidents=incidents,
    )
    assert "SolarWinds" in prompt
    assert "supply chain" in prompt


def test_prompt_handles_empty_incidents():
    prompt = build_user_prompt(
        domain="target.com",
        horizon_days=30,
        snapshot_text="",
        attack_surface_score=5.0,
        open_ports=[],
        cve_indicators=[],
        similar_incidents=[],
    )
    assert "No similar historical cases" in prompt


def test_prompt_contains_open_ports():
    prompt = build_user_prompt(
        domain="target.com",
        horizon_days=30,
        snapshot_text="",
        attack_surface_score=5.0,
        open_ports=[22, 443, 3389],
        cve_indicators=[],
        similar_incidents=[],
    )
    assert "3389" in prompt
