"""Computes the final risk signal by comparing model vs market probability."""

from __future__ import annotations

import logging

from threatsignal.models.schemas import FinalSignal, PolymarketResult

logger = logging.getLogger(__name__)


class SignalAggregator:
    def compute(self, model_prob: float, market_result: PolymarketResult) -> FinalSignal:
        risk_cat = self._categorize(model_prob)

        if market_result.status != "found" or market_result.probability is None:
            logger.info(
                "Signal computed: MARKET_NOT_AVAILABLE — model_prob=%.4f category=%s",
                model_prob,
                risk_cat,
            )
            return FinalSignal(
                model_probability=round(model_prob, 4),
                market_probability=None,
                delta=None,
                signal="MARKET_NOT_AVAILABLE",
                interpretation="No Polymarket data available. Model-only estimate provided.",
                risk_category=risk_cat,
            )

        market_prob = market_result.probability
        delta = round(model_prob - market_prob, 4)

        if delta > 0.10:
            signal = "MODEL_SEES_MORE_RISK"
            interp = (
                f"Model estimates {abs(delta)*100:.1f}pp MORE risk than the market. "
                "Possible information asymmetry — recent exposure data may not be "
                "priced into the market yet."
            )
        elif delta < -0.10:
            signal = "MARKET_SEES_MORE_RISK"
            interp = (
                f"Market prices {abs(delta)*100:.1f}pp MORE risk than the model. "
                "Check for recent news, active exploits, or ongoing incidents "
                "that may not be captured in static exposure data."
            )
        else:
            signal = "IN_LINE"
            interp = (
                f"Model ({model_prob:.2%}) and market ({market_prob:.2%}) are broadly "
                "aligned on risk (within ±10pp). No significant information asymmetry detected."
            )

        logger.info(
            "Signal computed: %s — model=%.4f market=%.4f delta=%+.4f category=%s",
            signal,
            model_prob,
            market_prob,
            delta,
            risk_cat,
        )
        return FinalSignal(
            model_probability=round(model_prob, 4),
            market_probability=round(market_prob, 4),
            delta=delta,
            signal=signal,
            interpretation=interp,
            risk_category=risk_cat,
        )

    def _categorize(self, prob: float) -> str:
        if prob < 0.10:
            return "LOW"
        if prob < 0.25:
            return "MEDIUM"
        if prob < 0.50:
            return "HIGH"
        return "CRITICAL"
