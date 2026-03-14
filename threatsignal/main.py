"""ThreatSignal AI — FastAPI application and CLI entry point."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

import typer
from fastapi import FastAPI, HTTPException

from threatsignal.config import settings
from threatsignal.embeddings.engine import EmbeddingEngine
from threatsignal.embeddings.index import BreachIndex
from threatsignal.llm.reasoner import LLMReasoner
from threatsignal.models.schemas import AnalyzeRequest, AnalyzeResponse
from threatsignal.polymarket.client import PolymarketClient
from threatsignal.report.builder import ReportBuilder
from threatsignal.shodan_client.client import ShodanClient
from threatsignal.shodan_client.normalizer import AttackSurfaceNormalizer
from threatsignal.signal.aggregator import SignalAggregator

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

    # 3. LLM assessment
    if settings.use_azure:
        llm = LLMReasoner(
            api_key=settings.azure_openai_api_key,
            model=settings.azure_llm_deployment,
            azure_endpoint=settings.azure_openai_endpoint,
            azure_api_version=settings.azure_openai_api_version,
        )
    else:
        llm = LLMReasoner(settings.openai_api_key, settings.llm_model)
    assessment = llm.assess(domain, surface, similar, time_horizon_days)

    # 4. Polymarket
    pm_client = PolymarketClient()
    polymarket = pm_client.search(domain)

    # 5. Signal
    signal = SignalAggregator().compute(assessment.probability, polymarket)

    # 6. Build report
    return ReportBuilder().build(domain, time_horizon_days, surface, similar, assessment, polymarket, signal)


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


@cli.command()
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
