"""Command-line interface for the IaC security workflow."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, replace
from pathlib import Path

from src.config import Settings, configure_logging
from src.embeddings.titan_embeddings import LocalHashEmbeddingClient, TitanEmbeddingClient
from src.knowledge.chunker import DocumentChunker
from src.knowledge.ingestion import KnowledgeIngestionPipeline
from src.knowledge.loader import KnowledgeLoader
from src.llm.factory import create_provider
from src.agents import ReportGenerationAgent, VulnerabilityDetectionAgent
from src.parser.cloudformation_parser import CloudFormationParser
from src.parser.normalizer import normalize_template
from src.retrieval.query_builder import build_resource_descriptors
from src.retrieval.retriever import RetrievalAgent, retrieval_results_to_dict
from src.retrieval.vector_store import LocalVectorStore
from src.workflow import SecurityAnalysisWorkflow


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        settings = Settings.from_env()
        configure_logging(settings)
        if args.command == "parse":
            return _parse_command(args)
        if args.command == "ingest":
            return _ingest_command(args, settings)
        if args.command == "retrieve":
            return _retrieve_command(args, settings)
        if args.command == "analyze":
            return _analyze_command(args, settings)
        if args.command == "auth":
            from src.llm.chatgpt_auth import ChatGPTAuth
            auth = ChatGPTAuth()
            if args.action == "login":
                print("Signed in:", auth.login(args.account))
            elif args.action == "logout":
                print("Signed out." if auth.logout() else "Signed out locally; remote revocation unconfirmed. Disconnect SecureIaC in ChatGPT Settings.")
            elif args.action == "select":
                auth.select(args.account)
            elif args.action == "models":
                from src.llm.chatgpt_provider import ChatGPTProvider
                print(json.dumps(ChatGPTProvider(settings.openai_model, auth=auth).models(auth.access_token()), indent=2))
            else:
                print(json.dumps(auth.accounts(), indent=2))
            return 0
        if args.command == "remediate":
            from src.remediation import remediate
            result, diff = remediate(args.template, args.patch, args.output, args.allow_property,
                settings.reports_path, args.policy or settings.policy_path, args.environment or settings.environment,
                args.region, settings.scanner_timeout)
            print(diff)
            print(json.dumps(result, indent=2, default=str))
            return 0 if result["status"] == "passed_checks" else 1
    except Exception as exc:
        from src.llm.base import LLMError
        print(f"error: {exc if isinstance(exc, LLMError) else type(exc).__name__ + ': check input, configuration and installed dependencies'}", file=sys.stderr)
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
    ingest_cmd.add_argument("--local-embeddings", action="store_true", help="Use cached local semantic embeddings (or explicit hash demo backend)")

    retrieve_cmd = subcommands.add_parser("retrieve", help="Retrieve security context for a template")
    retrieve_cmd.add_argument("template", type=Path)
    retrieve_cmd.add_argument("--local-embeddings", action="store_true", help="Use cached local semantic embeddings (or explicit hash demo backend)")
    retrieve_cmd.add_argument("--top-k", type=int, default=None)

    analyze_cmd = subcommands.add_parser("analyze", help="Run retrieval, detection, and reporting")
    analyze_cmd.add_argument("template", type=Path)
    analyze_cmd.add_argument("--output", type=Path, default=None)
    analyze_cmd.add_argument("--top-k", type=int, default=None)
    analyze_cmd.add_argument("--local-embeddings", action="store_true")
    analyze_cmd.add_argument("--verbose", action="store_true")
    analyze_cmd.add_argument("--provider", choices=["mock", "openai", "chatgpt", "bedrock"])
    analyze_cmd.add_argument("--deterministic-only", action="store_true")
    analyze_cmd.add_argument("--scan", action="store_true")
    analyze_cmd.add_argument("--policy", type=Path)
    analyze_cmd.add_argument("--environment")
    analyze_cmd.add_argument("--region")
    analyze_cmd.add_argument("--no-rag", action="store_true")
    analyze_cmd.add_argument("--no-relationships", action="store_true")
    auth_cmd = subcommands.add_parser("auth", help="Local ChatGPT-plan authentication")
    auth_cmd.add_argument("action", choices=["login", "logout", "status", "select", "models"])
    auth_cmd.add_argument("--account")
    remediation = subcommands.add_parser("remediate", help="Write and validate a separate property-patch candidate")
    remediation.add_argument("template", type=Path)
    remediation.add_argument("--patch", type=Path, required=True)
    remediation.add_argument("--output", type=Path, required=True)
    remediation.add_argument("--allow-property", action="append", required=True)
    remediation.add_argument("--policy", type=Path)
    remediation.add_argument("--environment")
    remediation.add_argument("--region")

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
    if settings.embedding_backend == "hash":
        return LocalHashEmbeddingClient()
    if force_local or settings.embedding_backend == "semantic":
        from src.embeddings.local_semantic import LocalSemanticEmbeddingClient
        return LocalSemanticEmbeddingClient(settings.embedding_model)
    if not settings.live_calls:
        raise ValueError("Titan embeddings require ENABLE_LIVE_CALLS=true")
    return TitanEmbeddingClient(
        region_name=settings.aws_region,
        model_id=settings.bedrock_embedding_model_id,
    )


def _analyze_command(args: argparse.Namespace, settings: Settings) -> int:
    if args.provider:
        settings = replace(settings, provider=args.provider)
    retrieval = None
    if not args.deterministic_only and not args.no_rag:
        embedder = _embedder(settings, force_local=args.local_embeddings)
        retrieval = RetrievalAgent(embedder, LocalVectorStore(settings.local_vector_store_path), top_k=args.top_k or settings.top_k_retrieval)
    llm = None if args.deterministic_only else create_provider(settings)
    from src.scanning import Scanner
    workflow = SecurityAnalysisWorkflow(
        retrieval_agent=retrieval,
        detection_agent=VulnerabilityDetectionAgent(llm, settings.max_attempts - 1, settings.max_input_bytes, settings.max_output_bytes) if llm else None,
        report_agent=ReportGenerationAgent(),
        parser=CloudFormationParser(settings.max_template_bytes),
        reports_dir=settings.reports_path,
        scanner=Scanner(timeout=settings.scanner_timeout) if args.scan else None,
        policy_path=args.policy or settings.policy_path,
        environment=args.environment or settings.environment, region=args.region,
        deterministic_only=args.deterministic_only, relationships=not args.no_relationships,
    )
    result = workflow.analyze(args.template, args.output)
    print(f"Analysis {result.analysis.analysis_metadata['status']}: {len(result.analysis.findings)} contextual finding(s)")
    metadata = result.analysis.analysis_metadata
    print(f"Scanner failures: {sum(f.get('outcome') == 'failed' for f in metadata['scanner']['findings'])}; policy violations: {sum(p['outcome'] == 'failed' for p in metadata['policies'])}")
    print(f"Report: {result.report_path}")
    if args.verbose:
        print(json.dumps(asdict(result.analysis), indent=2, default=str))
    return 1 if result.analysis.analysis_metadata["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
