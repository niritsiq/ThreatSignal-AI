"""RiskChart — scatter plot showing historical breach cases vs current domain."""

from __future__ import annotations

from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt

matplotlib.use("Agg")  # headless rendering, no display needed

from threatsignal.models.schemas import AnalyzeResponse, SimilarIncident

_DANGER_MAP = {
    "low": 0.10,
    "medium": 0.30,
    "high": 0.55,
    "critical": 0.80,
}

_COLOR_MAP = {
    "low": "#4caf50",
    "medium": "#ff9800",
    "high": "#f44336",
    "critical": "#9c27b0",
}


class RiskChart:
    def generate(self, response: AnalyzeResponse, output_dir: str = "reports") -> str:
        """Render scatter plot and save as PNG. Returns the file path."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        fig, ax = plt.subplots(figsize=(9, 6))

        # Plot historical breach cases
        points = self._breach_points(response.similar_incidents)
        for x, y, label, risk in points:
            color = _COLOR_MAP.get(risk, "#888888")
            ax.scatter(x, y, color=color, s=80, zorder=3)
            ax.annotate(label, (x, y), textcoords="offset points", xytext=(6, 4), fontsize=7)

        # Plot current domain as a gold star
        cx, cy = self._current_point(response)
        ax.scatter(cx, cy, marker="*", color="gold", edgecolors="black", s=300, zorder=5, label=response.meta.domain)
        ax.annotate(
            response.meta.domain,
            (cx, cy),
            textcoords="offset points",
            xytext=(8, 6),
            fontsize=9,
            fontweight="bold",
        )

        ax.set_xlabel("Exposure Score (Attack Surface)", fontsize=11)
        ax.set_ylabel("Danger Score (Breach Probability)", fontsize=11)
        ax.set_title("ThreatSignal — Risk Landscape", fontsize=13, fontweight="bold")
        ax.set_xlim(0, 10)
        ax.set_ylim(0, 1)
        ax.grid(True, linestyle="--", alpha=0.4)
        ax.legend(loc="upper left", fontsize=9)

        # Legend patches for risk levels
        from matplotlib.patches import Patch

        legend_elements = [Patch(facecolor=c, label=lvl.capitalize()) for lvl, c in _COLOR_MAP.items()]
        ax.legend(handles=legend_elements, loc="lower right", fontsize=8, title="Risk Level")

        ts = response.meta.generated_at.replace(":", "").replace("+", "").replace("-", "")[:15]
        filename = f"{response.meta.domain}_risk_chart_{ts}.png"
        path = str(Path(output_dir) / filename)
        fig.tight_layout()
        fig.savefig(path, dpi=120, bbox_inches="tight")
        plt.close(fig)
        return path

    def _breach_points(self, incidents: list[SimilarIncident]) -> list[tuple[float, float, str, str]]:
        """Return (x, y, label, risk_level) for each incident."""
        return [
            (
                self._exposure_score(inc.risk_level, inc.key_factors),
                self._danger_score(inc.risk_level),
                f"{inc.case_id} ({inc.year})",
                inc.risk_level.lower(),
            )
            for inc in incidents
        ]

    def _danger_score(self, risk_level: str) -> float:
        """Map risk_level string to a danger probability float."""
        return _DANGER_MAP.get(risk_level.lower(), 0.30)

    def _exposure_score(self, risk_level: str, key_factors: list[str]) -> float:
        """Combine risk level and number of key factors into an exposure score [0, 10]."""
        base = _DANGER_MAP.get(risk_level.lower(), 0.30) * 10  # 1.0 – 8.0
        factor_bonus = min(len(key_factors) * 0.5, 2.0)
        return min(base + factor_bonus, 10.0)

    def _current_point(self, response: AnalyzeResponse) -> tuple[float, float]:
        """Return (x, y) for the current domain: X=attack_surface_score, Y=llm_probability."""
        return (
            response.attack_surface.attack_surface_score,
            response.llm_assessment.probability,
        )
