"""RiskChart — scatter plot showing all historical breach cases vs current domain."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
from matplotlib.patches import Patch, Rectangle

matplotlib.use("Agg")  # headless rendering, no display needed

from threatsignal.embeddings.breach_dataset import load_cases
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

# (x, y, width, height, fill_color, label)
_ZONE_DEFS = [
    (0, 0.0, 5, 0.5, "#e8f5e9", "SAFE"),
    (0, 0.5, 5, 0.5, "#fff9c4", "MONITOR"),
    (5, 0.0, 5, 0.5, "#ffe0b2", "INVESTIGATE"),
    (5, 0.5, 5, 0.5, "#ffcdd2", "CRITICAL"),
]


class RiskChart:
    def __init__(self, breach_dataset_path: str = "data/breach_cases.jsonl"):
        self._dataset_path = breach_dataset_path

    def generate(self, response: AnalyzeResponse, output_dir: str = "reports") -> str:
        """Render scatter plot and save as PNG. Returns the file path."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        fig, ax = plt.subplots(figsize=(12, 7))

        # Background risk zones
        self._draw_zones(ax)

        # All breach cases — top-3 matches highlighted, rest dimmed
        top_ids = {inc.case_id for inc in response.similar_incidents}
        for case in self._load_all_cases():
            risk = case.get("risk_level", "medium").lower()
            x = self._exposure_score(risk, case.get("key_factors", []))
            y = self._danger_score(risk)
            color = _COLOR_MAP.get(risk, "#888888")
            is_match = case.get("case_id") in top_ids
            ax.scatter(
                x,
                y,
                color=color,
                s=130 if is_match else 55,
                alpha=1.0 if is_match else 0.35,
                edgecolors="black" if is_match else "none",
                linewidths=0.8 if is_match else 0,
                zorder=4 if is_match else 3,
            )
            title = case.get("title", case.get("case_id", ""))
            year = case.get("year", "")
            short = f"{title[:28]}… ({year})" if len(title) > 28 else f"{title} ({year})"
            ax.annotate(
                short,
                (x, y),
                textcoords="offset points",
                xytext=(6, 4),
                fontsize=6.5 if is_match else 5.5,
                fontweight="bold" if is_match else "normal",
                alpha=0.9 if is_match else 0.55,
            )

        # Current domain — gold star
        cx, cy = self._current_point(response)
        ax.scatter(
            cx,
            cy,
            marker="*",
            color="gold",
            edgecolors="#222222",
            s=600,
            linewidths=1.2,
            zorder=6,
        )
        ax.annotate(
            f"  {response.meta.domain}",
            (cx, cy),
            fontsize=10,
            fontweight="bold",
            color="#0d47a1",
            zorder=7,
        )

        ax.set_xlabel("Exposure Score  (Attack Surface  0 – 10)", fontsize=11)
        ax.set_ylabel("Danger Score  (Breach Probability  0 – 1)", fontsize=11)
        ax.set_title(
            f"ThreatSignal AI — Risk Landscape: {response.meta.domain}",
            fontsize=13,
            fontweight="bold",
            pad=14,
        )
        ax.set_xlim(0, 10)
        ax.set_ylim(0, 1)
        ax.grid(True, linestyle="--", alpha=0.25, zorder=1)

        # Single legend: risk level colors + current domain marker
        legend_elements = [
            Patch(facecolor=c, label=lvl.capitalize(), edgecolor="grey", linewidth=0.5) for lvl, c in _COLOR_MAP.items()
        ]
        legend_elements.append(
            Patch(facecolor="gold", edgecolor="#222222", linewidth=0.8, label=f"{response.meta.domain} (you)")
        )
        ax.legend(
            handles=legend_elements,
            loc="lower right",
            fontsize=8,
            title="Risk Level",
            title_fontsize=9,
            framealpha=0.9,
        )

        try:
            ts = datetime.fromisoformat(response.meta.generated_at).strftime("%Y%m%dT%H%M%S")
        except ValueError:
            ts = response.meta.generated_at[:19].replace(":", "").replace("-", "")

        filename = f"{response.meta.domain}_risk_chart_{ts}.png"
        path = str(Path(output_dir) / filename)
        fig.tight_layout()
        fig.savefig(path, dpi=130, bbox_inches="tight")
        plt.close(fig)
        return path

    def _draw_zones(self, ax) -> None:
        """Draw colored background quadrants (Safe / Monitor / Investigate / Critical)."""
        for x, y, w, h, color, label in _ZONE_DEFS:
            ax.add_patch(Rectangle((x, y), w, h, facecolor=color, alpha=0.30, zorder=0))
            ax.text(x + 0.15, y + 0.03, label, fontsize=7, color="#666666", alpha=0.75, zorder=1)

    def _load_all_cases(self) -> list[dict]:
        """Load all breach cases from the dataset file. Returns empty list on failure."""
        try:
            return load_cases(self._dataset_path)
        except Exception:
            return []

    def _breach_points(self, incidents: list[SimilarIncident]) -> list[tuple[float, float, str, str]]:
        """Return (x, y, label, risk_level) for each incident."""
        return [
            (
                self._exposure_score(inc.risk_level, inc.key_factors),
                self._danger_score(inc.risk_level),
                f"{inc.title} ({inc.year})",
                inc.risk_level.lower(),
            )
            for inc in incidents
        ]

    def _danger_score(self, risk_level: str) -> float:
        """Map risk_level string to a danger probability float."""
        return _DANGER_MAP.get(risk_level.lower(), 0.30)

    def _exposure_score(self, risk_level: str, key_factors: list[str]) -> float:
        """Combine risk level and number of key factors into an exposure score [0, 10]."""
        base = _DANGER_MAP.get(risk_level.lower(), 0.30) * 10
        factor_bonus = min(len(key_factors) * 0.5, 2.0)
        return min(base + factor_bonus, 10.0)

    def _current_point(self, response: AnalyzeResponse) -> tuple[float, float]:
        """Return (x, y) for the current domain: X=attack_surface_score, Y=llm_probability."""
        return (
            response.attack_surface.attack_surface_score,
            response.llm_assessment.probability,
        )
