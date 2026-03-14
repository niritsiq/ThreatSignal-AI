"""Risk trend comparison — TDD GREEN phase implementation."""

from __future__ import annotations

STABILITY_THRESHOLD = 0.05  # delta within ±5pp = STABLE


class RiskTrend:
    def compare(self, current_prob: float, previous_prob: float | None) -> dict:
        """Compare current vs previous risk probability and return a trend dict."""
        if previous_prob is None:
            return {
                "direction": "NEW",
                "delta": None,
                "current_category": self._categorize(current_prob),
                "previous_category": None,
                "severity_changed": False,
            }

        delta = round(current_prob - previous_prob, 4)
        cur_cat = self._categorize(current_prob)
        prev_cat = self._categorize(previous_prob)

        if delta > STABILITY_THRESHOLD:
            direction = "INCREASING"
        elif delta < -STABILITY_THRESHOLD:
            direction = "DECREASING"
        else:
            direction = "STABLE"

        return {
            "direction": direction,
            "delta": delta,
            "current_category": cur_cat,
            "previous_category": prev_cat,
            "severity_changed": cur_cat != prev_cat,
        }

    def _categorize(self, prob: float) -> str:
        if prob < 0.10:
            return "LOW"
        if prob < 0.25:
            return "MEDIUM"
        if prob < 0.50:
            return "HIGH"
        return "CRITICAL"
