"""LLM-based risk reasoning module — uses function calling for structured output."""

from __future__ import annotations

import json
import logging
import time

from openai import AzureOpenAI, OpenAI, RateLimitError

from threatsignal.llm.prompts import SYSTEM_PROMPT, build_user_prompt
from threatsignal.models.schemas import AttackSurface, LLMAssessment, SimilarIncident

logger = logging.getLogger(__name__)

# Tool definition: the LLM must call this function to submit its risk assessment.
# Using function calling instead of raw JSON mode gives us schema enforcement.
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "submit_risk_assessment",
            "description": "Submit the final structured cyber risk assessment for the target domain",
            "parameters": {
                "type": "object",
                "properties": {
                    "risk_level": {
                        "type": "string",
                        "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "description": "Overall risk level based on all available signals",
                    },
                    "probability": {
                        "type": "number",
                        "description": "Probability of a cyber incident in the given time horizon (0.0 to 1.0)",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence in the estimate (0.0 to 1.0)",
                    },
                    "main_drivers": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Top 3 risk factors driving the assessment",
                    },
                    "explanation": {
                        "type": "string",
                        "description": "Brief explanation of the risk assessment (max 200 words)",
                    },
                },
                "required": ["risk_level", "probability", "confidence", "main_drivers", "explanation"],
            },
        },
    }
]


class LLMReasoner:
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o-mini",
        azure_endpoint: str = "",
        azure_api_version: str = "",
        use_function_calling: bool = True,
    ):
        if azure_endpoint:
            self.client = AzureOpenAI(
                azure_endpoint=azure_endpoint,
                api_key=api_key,
                api_version=azure_api_version,
            )
            logger.info("LLMReasoner using Azure OpenAI endpoint: %s", azure_endpoint)
        else:
            self.client = OpenAI(api_key=api_key)
        self.model = model
        self.use_function_calling = use_function_calling

    def assess(
        self,
        domain: str,
        surface: AttackSurface,
        similar: list[SimilarIncident],
        horizon_days: int,
    ) -> LLMAssessment:
        """Call LLM and return structured risk assessment via function calling."""
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
                if self.use_function_calling:
                    return self._call_with_tools(user_prompt, attempt)
                else:
                    return self._call_json_mode(user_prompt, attempt)
            except RateLimitError:
                wait = 2**attempt
                logger.warning("LLM rate limit hit, waiting %ds (attempt %d/3)", wait, attempt + 1)
                time.sleep(wait)
            except (json.JSONDecodeError, KeyError, ValueError, IndexError) as e:
                logger.error("LLM response parse error (attempt %d): %s", attempt + 1, e)
                if attempt == 2:
                    return self._fallback_assessment()
        return self._fallback_assessment()

    def _call_with_tools(self, user_prompt: str, attempt: int) -> LLMAssessment:
        """Call LLM using OpenAI function calling — forces structured JSON output."""
        response = self.client.chat.completions.create(
            model=self.model,
            tools=TOOLS,
            tool_choice={"type": "function", "function": {"name": "submit_risk_assessment"}},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=600,
            timeout=30.0,
        )
        tool_call = response.choices[0].message.tool_calls[0]
        data = json.loads(tool_call.function.arguments)
        return LLMAssessment(
            risk_level=data["risk_level"],
            probability=float(data["probability"]),
            confidence=float(data["confidence"]),
            main_drivers=data.get("main_drivers", []),
            explanation=data.get("explanation", ""),
            model=self.model,
            prompt_tokens=response.usage.prompt_tokens,
            completion_tokens=response.usage.completion_tokens,
        )

    def _call_json_mode(self, user_prompt: str, attempt: int) -> LLMAssessment:
        """Fallback: call LLM with JSON response mode (no function calling)."""
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

    def _fallback_assessment(self) -> LLMAssessment:
        return LLMAssessment(
            risk_level="MEDIUM",
            probability=0.1,
            confidence=0.1,
            main_drivers=["LLM assessment unavailable"],
            explanation="The LLM assessment could not be completed. Manual review recommended.",
            model=self.model,
        )
