"""Orchestration for retrieval, detection, validation, and reporting."""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from src.agents import ReportGenerationAgent, VulnerabilityDetectionAgent
from src.models import RetrievalResult, TemplateAnalysisResult
from src.parser.cloudformation_parser import CloudFormationParser
from src.parser.normalizer import normalize_template
from src.retrieval.retriever import RetrievalAgent

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WorkflowResult:
    analysis: TemplateAnalysisResult
    report_path: Path
    report_markdown: str
    retrieval_results: list[RetrievalResult]


class SecurityAnalysisWorkflow:
    def __init__(
        self,
        retrieval_agent: RetrievalAgent,
        detection_agent: VulnerabilityDetectionAgent,
        report_agent: ReportGenerationAgent | None = None,
        parser: CloudFormationParser | None = None,
        reports_dir: str | Path = "reports",
    ) -> None:
        self.retrieval_agent = retrieval_agent
        self.detection_agent = detection_agent
        self.report_agent = report_agent or ReportGenerationAgent()
        self.parser = parser or CloudFormationParser()
        self.reports_dir = Path(reports_dir)

    def analyze(self, template_path: str | Path, output_path: str | Path | None = None) -> WorkflowResult:
        analysis_id = str(uuid.uuid4())
        started = datetime.now(timezone.utc)
        total_start = time.perf_counter()
        parsed = self.parser.parse_file(template_path)
        summary = normalize_template(parsed)

        retrieval_start = time.perf_counter()
        retrieval_results = self.retrieval_agent.retrieve(summary)
        retrieval_ms = _elapsed_ms(retrieval_start)

        llm_start = time.perf_counter()
        analysis = self.detection_agent.analyze(parsed, summary, retrieval_results)
        llm_ms = _elapsed_ms(llm_start)

        report_start = time.perf_counter()
        metadata = {
            "analysis_id": analysis_id,
            "start_time": started.isoformat(),
            "end_time": "pending",
            "retrieval_duration_ms": retrieval_ms,
            "llm_analysis_duration_ms": llm_ms,
            "resources_analyzed": len(parsed.resources),
            "retrieved_chunks": sum(len(item.retrieved_context) for item in retrieval_results),
            "model_id": self.detection_agent.llm.model_id,
        }
        analysis = replace(analysis, analysis_metadata=metadata)
        self.report_agent.generate(analysis, summary)
        report_ms = _elapsed_ms(report_start)
        metadata["report_generation_duration_ms"] = report_ms
        metadata["total_duration_ms"] = _elapsed_ms(total_start)
        metadata["end_time"] = datetime.now(timezone.utc).isoformat()
        analysis = replace(analysis, analysis_metadata=metadata)
        report = self.report_agent.generate(analysis, summary)

        destination = self._report_path(Path(template_path), output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(report, encoding="utf-8")
        logger.info(
            "Analysis completed analysis_id=%s resources=%s findings=%s report=%s",
            analysis_id, len(parsed.resources), len(analysis.findings), destination,
        )
        return WorkflowResult(analysis, destination, report, retrieval_results)

    def _report_path(self, template_path: Path, output_path: str | Path | None) -> Path:
        root = self.reports_dir.resolve()
        candidate = Path(output_path) if output_path else Path(f"{template_path.stem}-security-report.md")
        if not candidate.is_absolute():
            direct = candidate.resolve()
            candidate = direct if direct == root or root in direct.parents else self.reports_dir / candidate
        resolved = candidate.resolve()
        if resolved != root and root not in resolved.parents:
            raise ValueError(f"Report output must be within {root}")
        if resolved.suffix.lower() != ".md":
            raise ValueError("Report output must use the .md extension")
        return resolved


def _elapsed_ms(start: float) -> int:
    return round((time.perf_counter() - start) * 1000)
