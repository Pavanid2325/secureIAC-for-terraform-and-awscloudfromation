"""Logical agents in the security-analysis workflow."""

from .report_generation_agent import ReportGenerationAgent
from .vulnerability_detection_agent import VulnerabilityDetectionAgent

__all__ = ["ReportGenerationAgent", "VulnerabilityDetectionAgent"]
