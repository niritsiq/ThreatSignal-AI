"""
Build the FAISS breach index from breach_cases.jsonl.
Run once before starting the API: python scripts/build_index.py
"""
from __future__ import annotations
import json
import sys
import numpy as np
import faiss
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from threatsignal.config import settings
from threatsignal.embeddings.engine import EmbeddingEngine
from threatsignal.embeddings.breach_dataset import load_cases, save_cases


def build_index():
    print(f"Loading breach cases from {settings.breach_dataset_path}")
    cases = load_cases(settings.breach_dataset_path)
    if not cases:
        print("ERROR: No breach cases found. Add cases to data/breach_cases.jsonl first.")
        sys.exit(1)

    print(f"Found {len(cases)} cases. Embedding with {settings.embedding_model}...")
    engine = EmbeddingEngine(settings.openai_api_key, settings.embedding_model)

    texts = [
        f"{c.get('title', '')}. {c.get('summary', '')}. "
        f"Key factors: {', '.join(c.get('key_factors', []))}. "
        f"Industry: {c.get('industry', '')}."
        for c in cases
    ]

    embeddings_list = engine.embed_batch(texts)
    embeddings = np.array(embeddings_list, dtype="float32")
    print(f"Embeddings shape: {embeddings.shape}")

    # Normalize for cosine similarity
    faiss.normalize_L2(embeddings)

    # Build flat inner product index (= cosine similarity after L2 norm)
    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)
    print(f"FAISS index built: {index.ntotal} vectors, dimension {dim}")

    faiss.write_index(index, settings.faiss_index_path)
    print(f"Index saved to {settings.faiss_index_path}")

    # Strip embeddings from metadata and re-save
    for case in cases:
        case.pop("embedding", None)
    save_cases(cases, settings.breach_dataset_path)
    print(f"Metadata saved to {settings.breach_dataset_path}")
    print("Done! You can now start the API.")


if __name__ == "__main__":
    build_index()
