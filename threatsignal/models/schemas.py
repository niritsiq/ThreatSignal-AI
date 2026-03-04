from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator


class AnalyzeRequest(BaseModel):
    domain: str
    time_horizon_days: int = 30


class ServiceInfo(BaseModel):
    port: int
    product: str = "unknown"
    version: str = "unknown"
    cpe: str = ""


class AttackSurface(BaseModel):
    ips: list[str] = []
    open_ports: list[int] = []
    services: list[ServiceInfo] = []
    cve_indicators: list[str] = []
    hostnames: list[str] = []
    org: str = "unknown"
    country: str = "unknown"
    attack_surface_score: float = 0.0
    snapshot_text: str = ""


class SimilarIncident(BaseModel):
    rank: int
    case_id: str
    title: str
    year: int
    risk_level: str
    similarity_score: float
    key_factors: list[str] = []


class LLMAssessment(BaseModel):
    risk_level: str
    probability: float
    confidence: float
    main_drivers: list[str] = []
    explanation: str = ""
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @field_validator("probability", "confidence")
    @classmethod
    def clamp_0_1(cls, v: float) -> float:
        return max(0.0, min(1.0, v))

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, v: str) -> str:
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        v = v.upper()
        if v not in valid:
            raise ValueError(f"risk_level must be one of {valid}")
        return v


class PolymarketResult(BaseModel):
    status: str  # "found" | "not_found" | "error"
    market_id: str = ""
    question: str = ""
    probability: Optional[float] = None
    liquidity_usd: float = 0.0
    volume_usd: float = 0.0
    url: str = ""
    note: str = ""


class FinalSignal(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    model_probability: float
    market_probability: Optional[float] = None
    delta: Optional[float] = None
    signal: str  # "MODEL_SEES_MORE_RISK" | "MARKET_SEES_MORE_RISK" | "IN_LINE" | "MARKET_NOT_AVAILABLE"
    interpretation: str
    risk_category: str  # LOW | MEDIUM | HIGH | CRITICAL


class ReportMeta(BaseModel):
    request_id: str
    domain: str
    time_horizon_days: int
    generated_at: str
    version: str = "1.0.0"


class AnalyzeResponse(BaseModel):
    meta: ReportMeta
    attack_surface: AttackSurface
    similar_incidents: list[SimilarIncident]
    llm_assessment: LLMAssessment
    polymarket: PolymarketResult
    final_signal: FinalSignal
