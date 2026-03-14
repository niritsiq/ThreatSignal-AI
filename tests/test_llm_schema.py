"""Contract tests for LLM output schema validation."""

import pytest
from pydantic import ValidationError

from threatsignal.models.schemas import LLMAssessment


def test_valid_assessment():
    a = LLMAssessment(
        risk_level="HIGH", probability=0.31, confidence=0.72, main_drivers=["driver1"], explanation="test"
    )
    assert a.risk_level == "HIGH"


def test_probability_clamped_above_1():
    a = LLMAssessment(risk_level="LOW", probability=1.5, confidence=0.5)
    assert a.probability == 1.0


def test_probability_clamped_below_0():
    a = LLMAssessment(risk_level="LOW", probability=-0.5, confidence=0.5)
    assert a.probability == 0.0


def test_invalid_risk_level_raises():
    with pytest.raises(ValidationError):
        LLMAssessment(risk_level="EXTREME", probability=0.5, confidence=0.5)


def test_risk_level_case_insensitive():
    a = LLMAssessment(risk_level="high", probability=0.3, confidence=0.5)
    assert a.risk_level == "HIGH"


def test_main_drivers_defaults_to_empty():
    a = LLMAssessment(risk_level="LOW", probability=0.05, confidence=0.9)
    assert isinstance(a.main_drivers, list)
