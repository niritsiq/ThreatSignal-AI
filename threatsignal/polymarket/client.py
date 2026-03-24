"""Polymarket API client for prediction market probability lookup."""

from __future__ import annotations

import logging

import httpx

from threatsignal.models.schemas import PolymarketResult

logger = logging.getLogger(__name__)

GAMMA_API_BASE = "https://gamma-api.polymarket.com"
CYBER_KEYWORDS = {"hack", "breach", "cyber", "attack", "incident", "ransomware", "security"}
TIMEOUT = 15.0


class PolymarketClient:
    def search(self, domain: str) -> PolymarketResult:
        """Search Polymarket for a cyber-incident market related to the domain."""
        company = domain.split(".")[0].lower()

        try:
            with httpx.Client(timeout=TIMEOUT) as client:
                response = client.get(
                    f"{GAMMA_API_BASE}/markets",
                    params={"keyword": company, "limit": 10, "active": "true"},
                )
                response.raise_for_status()
                markets = response.json()
        except httpx.TimeoutException:
            logger.warning(f"Polymarket API timeout for {domain}")
            return PolymarketResult(status="error", note="API timeout")
        except Exception as e:
            logger.warning(f"Polymarket API error: {e}")
            return PolymarketResult(status="error", note=str(e))

        if not markets:
            return PolymarketResult(status="not_found", note=f"No active markets found for '{company}'")

        for market in markets:
            question = (market.get("question") or "").lower()
            if company in question and any(k in question for k in CYBER_KEYWORDS):
                logger.info("Polymarket cyber-incident market found for '%s': %s", company, market.get("question", ""))
                return self._parse_market(market)

        logger.info("No cyber-incident market found for '%s' among %d markets", company, len(markets))
        return PolymarketResult(
            status="not_found",
            note=f"No cyber-incident market found for '{company}' among {len(markets)} markets",
        )

    def _parse_market(self, market: dict) -> PolymarketResult:
        try:
            outcome_prices = market.get("outcomePrices", ["0", "1"])
            probability = float(outcome_prices[0]) if outcome_prices else 0.0
            return PolymarketResult(
                status="found",
                market_id=market.get("conditionId", ""),
                question=market.get("question", ""),
                probability=probability,
                liquidity_usd=float(market.get("liquidity", 0) or 0),
                volume_usd=float(market.get("volume", 0) or 0),
                url=f"https://polymarket.com/event/{market.get('slug', '')}",
            )
        except Exception as e:
            logger.error(f"Error parsing market: {e}")
            return PolymarketResult(status="error", note=str(e))
