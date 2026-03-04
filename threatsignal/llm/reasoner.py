"""LLM-based risk reasoning module."""
from __future__ import annotations

import json
import logging
import time

from openai import OpenAI, RateLimitError

from threatsignal.llm.prompts import SYSTEM_PROMPT, build_user_prompt
from threatsignal.models.schemas import AttackSurface, LLMAssessment, SimilarIncident

logger = logging.getLogger(__name__)


class LLMReasoner:
    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def assess(
        self,
        domain: str,
        surface: AttackSurface,
        similar: list[SimilarIncident],
        horizon_days: int,
    ) -> LLMAssessment:
        """Call LLM and return structured risk assessment."""
        user_prompt = build_user_prompt(
            domain=domain,
            horizon_days=horizon_days,
            snapshot_text=surface.snapshot_text,
            attack_surface_score=surface.attack_surface_score,
            open_ports=surface.open_ports,
            cve_indicators=surface.cve_indicators,
            similar_incidents=[inc.model_dump() for inc in similar],
        )

        for attempt in range(3):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0.2,
                    max_tokens=600,
                    timeout=30.0,
                )
                raw = response.choices[0].message.content
                data = json.loads(raw)
                return LLMAssessment(
                    risk_level=data.get("risk_level", "MEDIUM"),
                    probability=float(data.get("probability", 0.1)),
                    confidence=float(data.get("confidence", 0.5)),
                    main_drivers=data.get("main_drivers", []),
                    explanation=data.get("explanation", ""),
                    model=self.model,
                    prompt_tokens=response.usage.prompt_tokens,
                    completion_tokens=response.usage.completion_tokens,
                )
            except RateLimitError:
                wait = 2 ** attempt
                logger.warning(f"LLM rate limit hit, waiting {wait}s (attempt {attempt+1}/3)")
                time.sleep(wait)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                logger.error(f"LLM response parse error (attempt {attempt+1}): {e}")
                if attempt == 2:
                    return self._fallback_assessment()
        return self._fallback_assessment()

    def _fallback_assessment(self) -> LLMAssessment:
        return LLMAssessment(
            risk_level="MEDIUM",
            probability=0.1,
            confidence=0.1,
            main_drivers=["LLM assessment unavailable"],
            explanation="The LLM assessment could not be completed. Manual review recommended.",
            model=self.model,
        )
