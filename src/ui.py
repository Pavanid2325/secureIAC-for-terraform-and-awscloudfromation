"""Local Streamlit UI. Launch with python -m streamlit run src/ui.py."""
import json
import sys
import os
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dataclasses import asdict, replace
import streamlit as st
from src.config import Settings
from src.cli import _embedder
from src.llm.factory import create_provider
from src.agents import VulnerabilityDetectionAgent
from src.workflow import SecurityAnalysisWorkflow
from src.retrieval.retriever import RetrievalAgent
from src.retrieval.vector_store import LocalVectorStore
from src.scanning import Scanner

st.title("SecureIaC — local CloudFormation analysis")
st.caption("Report-only analysis. Uploaded configuration is sent to the selected provider only in live mode.")
settings = Settings.from_env()
mode = st.selectbox("Analysis mode", ["Deterministic only", "Demo", "Live LLM"])
st.text(f"Configured provider: {settings.provider}; authentication: {settings.auth_mode}; live enabled: {settings.live_calls}")
if settings.provider == "openai":
    st.text("API key configured: " + ("yes" if os.getenv("OPENAI_API_KEY") else "no"))
environment = st.selectbox("Operator-selected deployment environment", ["production", "staging", "development"])
region = st.text_input("Explicit deployment region (optional)")
policy_choices = [None, *sorted(Path("policies").glob("*.yaml"))]
policy = st.selectbox("Local policy file", policy_choices, format_func=lambda p: str(p) if p else "No policies")
use_scanner = st.checkbox("Run Checkov", value=True)
rag = st.checkbox("Retrieve local guidance", value=False)
upload = st.file_uploader("CloudFormation template", type=["yaml", "yml", "json"])
sample = st.selectbox("Sample", [None, *sorted(Path("examples").glob("**/*.yaml")), *sorted(Path("examples").glob("**/*.json"))], format_func=lambda p: str(p) if p else "Paste below")
text = st.text_area("Paste YAML or JSON", height=220)
if st.button("Analyze"):
    st.session_state.pop("analysis", None)
    st.session_state.pop("markdown", None)
    try:
        contents = upload.getvalue() if upload else sample.read_bytes() if sample else text.encode()
        if len(contents) > settings.max_template_bytes:
            raise ValueError("Template exceeds configured upload limit")
        suffix = Path(upload.name).suffix if upload else sample.suffix if sample else ".yaml"
        with tempfile.TemporaryDirectory(prefix="secureiac-ui-") as directory:
            template = Path(directory) / ("upload" + suffix)
            template.write_bytes(contents)
            with st.status("Preparing analysis", expanded=True) as progress:
                local_settings = replace(settings, provider="mock") if mode == "Demo" else settings
                deterministic = mode == "Deterministic only"
                if mode == "Live LLM" and settings.provider == "mock":
                    raise ValueError("Configure a live provider before selecting Live LLM")
                st.write("Preparing parser, scanner, policies and optional retrieval.")
                retrieval = RetrievalAgent(_embedder(local_settings), LocalVectorStore(settings.local_vector_store_path), settings.top_k_retrieval) if rag and not deterministic else None
                detection = None if deterministic else VulnerabilityDetectionAgent(create_provider(local_settings), settings.max_attempts-1, settings.max_input_bytes, settings.max_output_bytes)
                workflow = SecurityAnalysisWorkflow(retrieval, detection, reports_dir=Path(directory)/"reports", scanner=Scanner(timeout=settings.scanner_timeout) if use_scanner else None,
                    policy_path=policy, environment=environment, region=region or None, deterministic_only=deterministic)
                result = workflow.analyze(template)
                progress.update(label="Analysis " + result.analysis.analysis_metadata["status"], state="complete" if result.analysis.analysis_metadata["status"] == "complete" else "error")
                st.session_state["analysis"] = asdict(result.analysis)
                st.session_state["markdown"] = result.report_markdown
    except Exception as exc:
        st.error("Analysis failed: " + type(exc).__name__ + ". Check configuration, input format, model cache and local tool installation.")
if "analysis" in st.session_state:
    st.json(st.session_state["analysis"])
    st.download_button("Download JSON", json.dumps(st.session_state["analysis"], indent=2, default=str), "analysis.json", "application/json")
    st.download_button("Download Markdown", st.session_state["markdown"], "analysis.md", "text/markdown")
