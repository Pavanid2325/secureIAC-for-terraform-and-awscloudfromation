"""Command-line interface for the IaC security workflow."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from src.config import Settings, configure_logging
from src.embeddings.titan_embeddings import LocalHashEmbeddingClient, TitanEmbeddingClient
from src.knowledge.chunker import DocumentChunker
from src.knowledge.ingestion import KnowledgeIngestionPipeline
from src.knowledge.loader import KnowledgeLoader
from src.llm import BedrockClaudeClient
from src.agents import ReportGenerationAgent, VulnerabilityDetectionAgent
from src.parser.cloudformation_parser import CloudFormationParser
from src.parser.normalizer import normalize_template
from src.retrieval.query_builder import build_resource_descriptors
from src.retrieval.retriever import RetrievalAgent, retrieval_results_to_dict
from src.retrieval.vector_store import LocalVectorStore
from src.workflow import SecurityAnalysisWorkflow


def main(argv: list[str] | None = None) -> int:
    settings = Settings.from_env()
    configure_logging(settings)
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "parse":
            return _parse_command(args)
        if args.command == "ingest":
            return _ingest_command(args, settings)
        if args.command == "retrieve":
            return _retrieve_command(args, settings)
        if args.command == "analyze":
            return _analyze_command(args, settings)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RAG-grounded IaC security analysis CLI")
    subcommands = parser.add_subparsers(dest="command", required=True)

    parse_cmd = subcommands.add_parser("parse", help="Parse and normalize a CloudFormation template")
    parse_cmd.add_argument("template", type=Path)
    parse_cmd.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    ingest_cmd = subcommands.add_parser("ingest", help="Ingest local security guidance")
    ingest_cmd.add_argument("--path", type=Path, default=None)
    ingest_cmd.add_argument("--local-embeddings", action="store_true", help="Use deterministic local embeddings")

    retrieve_cmd = subcommands.add_parser("retrieve", help="Retrieve security context for a template")
    retrieve_cmd.add_argument("template", type=Path)
    retrieve_cmd.add_argument("--local-embeddings", action="store_true", help="Use deterministic local embeddings")
    retrieve_cmd.add_argument("--top-k", type=int, default=None)

    analyze_cmd = subcommands.add_parser("analyze", help="Run retrieval, detection, and reporting")
    analyze_cmd.add_argument("template", type=Path)
    analyze_cmd.add_argument("--output", type=Path, default=None)
    analyze_cmd.add_argument("--top-k", type=int, default=None)
    analyze_cmd.add_argument("--local-embeddings", action="store_true")
    analyze_cmd.add_argument("--verbose", action="store_true")

    return parser


def _parse_command(args: argparse.Namespace) -> int:
    parsed = CloudFormationParser().parse_file(args.template)
    summary = normalize_template(parsed)
    if args.json:
        print(json.dumps(asdict(summary), indent=2, default=str))
    else:
        print(summary.summary)
        for resource in summary.normalized_resources:
            print()
            print(resource.summary)
    return 0


def _ingest_command(args: argparse.Namespace, settings: Settings) -> int:
    embedder = _embedder(settings, force_local=args.local_embeddings)
    store = LocalVectorStore(settings.local_vector_store_path)
    pipeline = KnowledgeIngestionPipeline(
        loader=KnowledgeLoader(),
        chunker=DocumentChunker(settings.chunk_size, settings.chunk_overlap),
        embedder=embedder,
        vector_store=store,
    )
    stats = pipeline.ingest(args.path or settings.knowledge_base_path)
    print(json.dumps(asdict(stats), indent=2))
    return 0


def _retrieve_command(args: argparse.Namespace, settings: Settings) -> int:
    parsed = CloudFormationParser().parse_file(args.template)
    summary = normalize_template(parsed)
    descriptors = build_resource_descriptors(summary)
    print("Resource descriptors:")
    for descriptor in descriptors:
        print(f"- {descriptor.resource} ({descriptor.resource_type})")
        print(f"  query: {descriptor.query}")

    embedder = _embedder(settings, force_local=args.local_embeddings)
    store = LocalVectorStore(settings.local_vector_store_path)
    agent = RetrievalAgent(embedder, store, top_k=args.top_k or settings.top_k_retrieval)
    results = agent.retrieve(summary)

    print("\nRetrieved security context:")
    for result in retrieval_results_to_dict(results):
        print(f"- {result['resource']} ({result['resource_type']})")
        print(f"  query: {result['query']}")
        for context in result["retrieved_context"]:
            print(
                f"  score={context['score']:.4f} "
                f"chunk={context['chunk_id']} source={context['source']}"
            )
    return 0


def _embedder(settings: Settings, force_local: bool = False):
    if force_local or settings.use_local_embeddings:
        return LocalHashEmbeddingClient()
    return TitanEmbeddingClient(
        region_name=settings.aws_region,
        model_id=settings.bedrock_embedding_model_id,
    )


def _analyze_command(args: argparse.Namespace, settings: Settings) -> int:
    embedder = _embedder(settings, force_local=args.local_embeddings)
    retrieval = RetrievalAgent(
        embedder,
        LocalVectorStore(settings.local_vector_store_path),
        top_k=args.top_k or settings.top_k_retrieval,
    )
    llm = BedrockClaudeClient(
        region_name=settings.aws_region,
        model_id=settings.bedrock_llm_model_id,
        temperature=settings.llm_temperature,
        max_tokens=settings.llm_max_tokens,
        max_retries=settings.llm_max_retries,
    )
    workflow = SecurityAnalysisWorkflow(
        retrieval_agent=retrieval,
        detection_agent=VulnerabilityDetectionAgent(llm),
        report_agent=ReportGenerationAgent(),
        parser=CloudFormationParser(settings.max_template_bytes),
        reports_dir=settings.reports_path,
    )
    result = workflow.analyze(args.template, args.output)
    print(f"Analysis complete: {len(result.analysis.findings)} finding(s)")
    print(f"Report: {result.report_path}")
    if args.verbose:
        print(json.dumps(asdict(result.analysis), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
