"""ThreatSignal AI — FastAPI application and CLI entry point."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

import typer
from fastapi import FastAPI, HTTPException

from threatsignal.config import settings
from threatsignal.embeddings.engine import EmbeddingEngine
from threatsignal.embeddings.index import BreachIndex
from threatsignal.llm.reasoner import LLMReasoner
from threatsignal.models.schemas import AnalyzeRequest, AnalyzeResponse, NewsSignal, TrendResult
from threatsignal.news.client import NewsClient
from threatsignal.polymarket.client import PolymarketClient
from threatsignal.report.builder import ReportBuilder
from threatsignal.shodan_client.client import ShodanClient
from threatsignal.shodan_client.normalizer import AttackSurfaceNormalizer
from threatsignal.signal.aggregator import SignalAggregator
from threatsignal.signal.trend import RiskTrend

logging.basicConfig(level=getattr(logging, settings.log_level, logging.INFO))
logger = logging.getLogger(__name__)

breach_index = BreachIndex()


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        breach_index.load(settings.faiss_index_path, settings.breach_dataset_path)
        logger.info("Breach index loaded successfully")
    except Exception as e:
        logger.warning(f"Could not load breach index: {e}. Similarity search disabled.")
    yield


app = FastAPI(
    title="ThreatSignal AI",
    description="Cyber incident risk estimation via Shodan + Embeddings + LLM + Polymarket",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0"}


def _load_previous_probability(domain: str, reports_dir: str = "reports") -> float | None:
    """Return the LLM probability from the most recent saved report for this domain."""
    report_path = Path(reports_dir)
    if not report_path.exists():
        return None
    files = sorted(report_path.glob(f"{domain}_*.json"))
    if not files:
        return None
    try:
        with open(files[-1], encoding="utf-8") as f:
            data = json.load(f)
        return data.get("llm_assessment", {}).get("probability")
    except Exception as e:
        logger.warning(f"Could not read previous report for {domain}: {e}")
        return None


def _ensure_index_loaded():
    """Load breach index if not yet loaded — supports both CLI and API modes."""
    if breach_index.index is None:
        try:
            breach_index.load(settings.faiss_index_path, settings.breach_dataset_path)
            logger.info("Breach index loaded")
        except Exception as e:
            logger.warning(f"Could not load breach index: {e}. Similarity search disabled.")


async def _run_analysis(domain: str, time_horizon_days: int) -> AnalyzeResponse:
    """Core analysis pipeline."""
    # 0. Ensure FAISS index is loaded (CLI doesn't go through FastAPI lifespan)
    _ensure_index_loaded()

    # 1. Shodan
    shodan_client = ShodanClient(settings.shodan_api_key)
    raw = shodan_client.query_domain(domain)
    surface = AttackSurfaceNormalizer().parse(raw, domain)

    # 2. Embeddings + similarity
    if settings.use_azure:
        embedding_engine = EmbeddingEngine(
            api_key=settings.azure_openai_api_key,
            model=settings.azure_embedding_deployment,
            azure_endpoint=settings.azure_openai_endpoint,
            azure_api_version=settings.azure_openai_api_version,
        )
    else:
        embedding_engine = EmbeddingEngine(settings.openai_api_key, settings.embedding_model)
    query_vec = embedding_engine.embed(surface.snapshot_text)
    similar = breach_index.search(query_vec, top_k=settings.top_k_similar)

    # 3. News signal — fetch recent cyber headlines via SerpAPI
    news_signal = None
    if settings.serp_api_key:
        news_client = NewsClient(api_key=settings.serp_api_key)
        raw_news = news_client.search(domain)
        news_signal = NewsSignal(
            article_count=raw_news.article_count,
            headlines=raw_news.headlines,
            risk_boost=raw_news.risk_boost,
        )
    else:
        logger.warning("SERP_API_KEY not set — skipping news signal")

    # 4. LLM assessment — pass headlines so GPT can factor them in
    news_headlines = news_signal.headlines if news_signal else None
    if settings.use_azure:
        llm = LLMReasoner(
            api_key=settings.azure_openai_api_key,
            model=settings.azure_llm_deployment,
            azure_endpoint=settings.azure_openai_endpoint,
            azure_api_version=settings.azure_openai_api_version,
        )
    else:
        llm = LLMReasoner(settings.openai_api_key, settings.llm_model)
    assessment = llm.assess(domain, surface, similar, time_horizon_days, news_headlines=news_headlines)

    # 5. Polymarket
    pm_client = PolymarketClient()
    polymarket = pm_client.search(domain)

    # 6. Signal — apply news boost to model probability before comparison
    boosted_prob = assessment.probability
    if news_signal and news_signal.risk_boost > 0:
        boosted_prob = min(assessment.probability + news_signal.risk_boost, 1.0)
        logger.info(
            "News boost applied: %.2f + %.2f = %.2f", assessment.probability, news_signal.risk_boost, boosted_prob
        )
    signal = SignalAggregator().compute(boosted_prob, polymarket)

    # 7. Build report
    response = ReportBuilder().build(domain, time_horizon_days, surface, similar, assessment, polymarket, signal)
    response.news = news_signal

    # 8. Risk trend — compare current probability against the most recent saved report
    previous_prob = _load_previous_probability(domain)
    trend_dict = RiskTrend().compare(assessment.probability, previous_prob)
    response.trend = TrendResult(**trend_dict)

    return response


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    try:
        return await asyncio.get_event_loop().run_in_executor(
            None, lambda: asyncio.run(_run_analysis(request.domain, request.time_horizon_days))
        )
    except Exception as e:
        logger.error(f"Analysis failed for {request.domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


# ── CLI ────────────────────────────────────────────────────────────────────────
cli = typer.Typer(help="ThreatSignal AI — Cyber incident risk estimator")


@cli.command("analyze")
def analyze_cmd(
    domain: str = typer.Option(..., "--domain", "-d", help="Target domain (e.g. okta.com)"),
    horizon: int = typer.Option(30, "--horizon", "-h", help="Time horizon in days"),
    save: bool = typer.Option(True, "--save/--no-save", help="Save JSON report to ./reports/"),
):
    """Analyze a domain's cyber incident risk."""
    import asyncio

    result = asyncio.run(_run_analysis(domain, horizon))
    ReportBuilder().print_cli(result)
    if save:
        path = ReportBuilder().save_json(result)
        typer.echo(f"\nJSON report saved to: {path}")


@cli.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Host to bind"),
    port: int = typer.Option(8000, help="Port to bind"),
):
    """Start the FastAPI server."""
    import uvicorn

    uvicorn.run("threatsignal.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    cli()
