"""RiskChart — scatter plot showing all historical breach cases vs current domain."""

from __future__ import annotations

from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

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

# (xmin, xmax, ymin_frac, ymax_frac, fill_color, text_color, label, label_x, label_y)
# ymin/ymax are axis fractions (0=bottom, 1=top) as required by axvspan
_ZONE_DEFS = [
    (0, 5, 0.0, 0.5, "#a5d6a7", "#1b5e20", "SAFE", 2.5, 0.25),
    (0, 5, 0.5, 1.0, "#fff176", "#f57f17", "MONITOR", 2.5, 0.75),
    (5, 10, 0.0, 0.5, "#ffcc80", "#e65100", "INVESTIGATE", 7.5, 0.25),
    (5, 10, 0.5, 1.0, "#ef9a9a", "#b71c1c", "CRITICAL", 7.5, 0.75),
]


class RiskChart:
    def generate(self, response: AnalyzeResponse, output_dir: str = "reports") -> str:
        """Render scatter plot and save as PNG. Returns the file path."""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        fig, ax = plt.subplots(figsize=(12, 7))

        # Background risk zones
        self._draw_zones(ax)

        # Top-3 similar incidents — stagger vertical offsets so labels never overlap
        label_offsets = [(8, 5), (8, 22), (8, -16)]
        for i, (x, y, label, risk) in enumerate(self._breach_points(response.similar_incidents)):
            color = _COLOR_MAP.get(risk, "#888888")
            ax.scatter(x, y, color=color, s=130, edgecolors="black", linewidths=0.8, zorder=4)
            ox, oy = label_offsets[i % len(label_offsets)]
            ax.annotate(
                label,
                (x, y),
                textcoords="offset points",
                xytext=(ox, oy),
                fontsize=8,
                fontweight="bold",
                color="#333333",
                bbox=dict(boxstyle="round,pad=0.2", facecolor="white", alpha=0.7, edgecolor="none"),
                arrowprops=dict(arrowstyle="-", color="#aaaaaa", lw=0.8),
            )

        # Current domain — gold star
        cx, cy = self._current_point(response)
        ax.scatter(cx, cy, marker="*", color="gold", edgecolors="#222222", s=600, linewidths=1.2, zorder=6)
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
            handles=legend_elements, loc="lower right", fontsize=8, title="Risk Level", title_fontsize=9, framealpha=0.9
        )

        # Fixed filename per domain — overwrites previous chart, no multiple windows
        filename = f"{response.meta.domain}_risk_chart.png"
        path = str(Path(output_dir) / filename)
        fig.tight_layout()
        fig.savefig(path, dpi=130, bbox_inches="tight")
        plt.close(fig)
        return path

    def _draw_zones(self, ax) -> None:
        """Draw colored background quadrants (Safe / Monitor / Investigate / Critical)."""
        for xmin, xmax, ymin, ymax, color, text_color, label, lx, ly in _ZONE_DEFS:
            ax.axvspan(xmin, xmax, ymin=ymin, ymax=ymax, facecolor=color, alpha=0.45, zorder=0)
            ax.text(
                lx,
                ly,
                label,
                fontsize=14,
                fontweight="bold",
                color=text_color,
                alpha=0.40,
                ha="center",
                va="center",
                zorder=1,
            )

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
