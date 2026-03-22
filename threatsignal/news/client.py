"""NewsClient — fetches recent cyber-related news via SerpAPI Google News search."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

SERP_API_URL = "https://serpapi.com/search.json"
TIMEOUT = 10.0


@dataclass
class NewsSignal:
    article_count: int = 0
    headlines: list[str] = field(default_factory=list)
    risk_boost: float = 0.0
    source: str = "serpapi"


class NewsClient:
    def __init__(self, api_key: str):
        self.api_key = api_key

    def search(self, domain: str, days: int = 30) -> NewsSignal:
        """Search SerpAPI for recent cyber-incident news about the target domain."""
        company = domain.split(".")[0]
        query = f"{company} hack breach cyber attack security"

        try:
            response = httpx.get(
                SERP_API_URL,
                params={
                    "q": query,
                    "tbm": "nws",
                    "tbs": "qdr:m",
                    "num": 10,
                    "api_key": self.api_key,
                },
                timeout=TIMEOUT,
            )
            data = response.json()
        except httpx.TimeoutException:
            logger.warning("SerpAPI timeout for %s", domain)
            return NewsSignal()
        except Exception as e:
            logger.warning("SerpAPI error for %s: %s", domain, e)
            return NewsSignal()

        results = data.get("news_results", [])
        headlines = [r.get("title", "") for r in results[:5]]
        count = len(results)
        boost = self._compute_boost(count)

        logger.info("NewsClient: %d articles found for %s — risk boost +%.0f%%", count, domain, boost * 100)
        return NewsSignal(article_count=count, headlines=headlines, risk_boost=boost)

    def _compute_boost(self, count: int) -> float:
        if count == 0:
            return 0.0
        if count <= 2:
            return 0.05
        if count <= 5:
            return 0.10
        return 0.15
