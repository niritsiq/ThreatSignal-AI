"""Builds the final report in JSON and CLI-readable format."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from threatsignal.models.schemas import (
    AnalyzeResponse,
    AttackSurface,
    FinalSignal,
    LLMAssessment,
    PolymarketResult,
    ReportMeta,
    SimilarIncident,
)

logger = logging.getLogger(__name__)

RISK_COLORS = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}


class ReportBuilder:
    def build(
        self,
        domain: str,
        time_horizon_days: int,
        surface: AttackSurface,
        similar: list[SimilarIncident],
        llm: LLMAssessment,
        polymarket: PolymarketResult,
        signal: FinalSignal,
    ) -> AnalyzeResponse:
        return AnalyzeResponse(
            meta=ReportMeta(
                request_id=str(uuid.uuid4()),
                domain=domain,
                time_horizon_days=time_horizon_days,
                generated_at=datetime.now(timezone.utc).isoformat(),
            ),
            attack_surface=surface,
            similar_incidents=similar,
            llm_assessment=llm,
            polymarket=polymarket,
            final_signal=signal,
        )

    def save_json(self, response: AnalyzeResponse, output_dir: str = "reports") -> str:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"{output_dir}/{response.meta.domain}_{ts}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(response.model_dump(), f, indent=2, ensure_ascii=False)
        logger.info("Report saved to %s", path)
        return path

    def print_cli(self, response: AnalyzeResponse):
        console = Console()
        r = response
        color = RISK_COLORS.get(r.final_signal.risk_category, "white")

        console.print(
            Panel(
                f"[bold]ThreatSignal AI — Risk Report[/bold]\n"
                f"Target  : [cyan]{r.meta.domain}[/cyan]\n"
                f"Horizon : {r.meta.time_horizon_days} days\n"
                f"Generated: {r.meta.generated_at}",
                box=box.DOUBLE,
                expand=False,
            )
        )

        # Section 1: Attack Surface
        console.print("\n[bold underline][1] ATTACK SURFACE SUMMARY[/bold underline]")
        console.print(f"  IPs found        : {', '.join(r.attack_surface.ips) or 'none'}")
        console.print(f"  Open ports       : {r.attack_surface.open_ports}")
        services_str = ", ".join(f"{s.product}/{s.version}" for s in r.attack_surface.services[:5])
        console.print(f"  Technologies     : {services_str or 'none detected'}")
        console.print(f"  CVE indicators   : {', '.join(r.attack_surface.cve_indicators) or 'none'}")
        console.print(f"  Organization     : {r.attack_surface.org} ({r.attack_surface.country})")
        score_color = (
            "green"
            if r.attack_surface.attack_surface_score < 4
            else ("yellow" if r.attack_surface.attack_surface_score < 7 else "red")
        )
        console.print(
            f"  [bold]Attack Surface Score: [{score_color}]{r.attack_surface.attack_surface_score}/10[/{score_color}][/bold]"
        )

        # Section 2: Similar Incidents
        console.print("\n[bold underline][2] SIMILAR HISTORICAL BREACHES[/bold underline]")
        table = Table(box=box.SIMPLE)
        table.add_column("#", style="dim", width=3)
        table.add_column("Incident", min_width=35)
        table.add_column("Similarity", justify="right", width=12)
        table.add_column("Risk", width=10)
        for inc in r.similar_incidents:
            rl = inc.risk_level.upper()
            table.add_row(
                str(inc.rank),
                inc.title,
                f"{inc.similarity_score:.2f}",
                Text(rl, style=RISK_COLORS.get(rl, "white")),
            )
        console.print(table)

        # Section 3: LLM Assessment
        console.print("\n[bold underline][3] LLM RISK ASSESSMENT[/bold underline]")
        rl = r.llm_assessment.risk_level
        console.print(
            f"  Risk Level    : [{RISK_COLORS.get(rl,'white')}][bold]{rl}[/bold][/{RISK_COLORS.get(rl,'white')}]"
        )
        console.print(
            f"  Probability   : [bold]{r.llm_assessment.probability:.2%}[/bold] chance within {r.meta.time_horizon_days} days"
        )
        console.print(f"  Confidence    : {r.llm_assessment.confidence:.2%}")
        console.print("  Main Drivers  :")
        for driver in r.llm_assessment.main_drivers:
            console.print(f"    - {driver}")
        console.print(f"\n  [italic]{r.llm_assessment.explanation}[/italic]")

        # Section 4: News Signal
        if r.news is not None:
            console.print("\n[bold underline][4] NEWS SIGNAL (SerpAPI)[/bold underline]")
            news = r.news
            if news.article_count == 0:
                console.print("  Articles found  : [dim]0 — no recent cyber news detected[/dim]")
            else:
                boost_color = "red" if news.risk_boost >= 0.10 else ("yellow" if news.risk_boost > 0 else "green")
                console.print(f"  Articles found  : [{boost_color}][bold]{news.article_count}[/bold][/{boost_color}]")
                console.print(f"  Risk boost      : [{boost_color}]+{news.risk_boost:.0%}[/{boost_color}]")
                console.print("  Recent headlines:")
                for headline in news.headlines[:3]:
                    console.print(f"    - {headline}")

        # Section 5: Polymarket

        console.print("\n[bold underline][5] POLYMARKET SIGNAL[/bold underline]")
        pm = r.polymarket
        if pm.status == "found":
            console.print(f"  Market        : {pm.question}")
            console.print(f"  Market Prob   : [bold]{pm.probability:.2%}[/bold]")
            console.print(f"  Liquidity     : ${pm.liquidity_usd:,.0f}")
            console.print("  Status        : [green]FOUND[/green]")
        else:
            console.print(f"  Status        : [dim]NOT FOUND[/dim] — {pm.note}")

        # Section 6: Final Signal
        console.print("\n[bold underline][6] FINAL SIGNAL[/bold underline]")
        sig = r.final_signal
        console.print(f"  Model Probability  : [bold]{sig.model_probability:.2%}[/bold]")
        if sig.market_probability is not None:
            console.print(f"  Market Probability : [bold]{sig.market_probability:.2%}[/bold]")
            delta_color = "red" if (sig.delta or 0) > 0.05 else ("yellow" if (sig.delta or 0) > 0 else "green")
            console.print(f"  Delta              : [{delta_color}]{sig.delta:+.4f}[/{delta_color}]")
        signal_color = {
            "MODEL_SEES_MORE_RISK": "red",
            "MARKET_SEES_MORE_RISK": "yellow",
            "IN_LINE": "green",
            "MARKET_NOT_AVAILABLE": "dim",
        }.get(sig.signal, "white")
        console.print(f"  Signal             : [{signal_color}][bold]{sig.signal}[/bold][/{signal_color}]")
        console.print(f"  Interpretation     : {sig.interpretation}")
        console.print(f"\n  [bold]Overall Risk Category: [{color}]{sig.risk_category}[/{color}][/bold]")

        # Section 7: Risk Trend
        if r.trend is not None:
            console.print("\n[bold underline][7] RISK TREND[/bold underline]")
            trend = r.trend
            direction_icons = {"INCREASING": "^", "DECREASING": "v", "STABLE": "-", "NEW": "*"}
            direction_colors = {"INCREASING": "red", "DECREASING": "green", "STABLE": "yellow", "NEW": "cyan"}
            icon = direction_icons.get(trend.direction, "?")
            tc = direction_colors.get(trend.direction, "white")
            console.print(f"  Direction   : [{tc}][bold]{icon} {trend.direction}[/bold][/{tc}]")
            if trend.delta is not None:
                console.print(f"  Delta       : [{tc}]{trend.delta:+.2%}[/{tc}]")
            console.print(f"  Now         : {trend.current_category}")
            if trend.previous_category:
                console.print(f"  Previously  : {trend.previous_category}")
            if trend.severity_changed:
                console.print("  [bold yellow]⚠ Severity category changed![/bold yellow]")

        console.print(Panel("", box=box.DOUBLE, expand=True))
