"""Streamlit UI for TriageSBOM — SBOM vulnerability prioritizer."""

import json
import tempfile
from pathlib import Path

import streamlit as st
from triagesbom.pipeline import run_offline, run_live, DEFAULT_SBOM

st.set_page_config(
    page_title="TriageSBOM",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("TriageSBOM")
st.markdown(
    "Upload a CycloneDX SBOM and rank its vulnerabilities by exploit risk — "
    "EPSS, CISA KEV, and CVSS — not just severity."
)

st.sidebar.header("Configuration")

offline_mode = st.sidebar.toggle("Offline mode (no network)", value=True)
st.sidebar.caption("Uses bundled fixtures. Uncheck for live OSV/EPSS/KEV lookups.")

st.sidebar.markdown("---")
st.sidebar.subheader("Scoring Weights")

kev_boost = st.sidebar.number_input(
    "KEV Boost (active exploitation escalator)",
    min_value=0.0,
    value=100.0,
    step=10.0,
    help="Any KEV-listed CVE outranks non-KEV by this amount.",
)

epss_weight = st.sidebar.number_input(
    "EPSS Weight (exploit probability)",
    min_value=0.0,
    value=30.0,
    step=1.0,
)

cvss_weight = st.sidebar.number_input(
    "CVSS Weight (severity 0-10)",
    min_value=0.0,
    value=20.0,
    step=1.0,
)

st.sidebar.markdown("---")
st.sidebar.caption(
    "Formula: risk = (kev_boost if KEV else 0) + epss_weight × epss + cvss_weight × (cvss/10)"
)

col1, col2 = st.columns([2, 1])

with col1:
    uploaded_file = st.file_uploader(
        "Upload CycloneDX SBOM (JSON)",
        type=["json"],
        accept_multiple_files=False,
    )

with col2:
    st.markdown("### Presets")
    if st.button("Load Sample"):
        st.session_state.sbom_path = str(DEFAULT_SBOM)
        st.session_state.sbom_name = "sample.cdx.json"

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as f:
        f.write(uploaded_file.getbuffer())
        st.session_state.sbom_path = f.name
        st.session_state.sbom_name = uploaded_file.name

if "sbom_path" in st.session_state:
    sbom_path = st.session_state.sbom_path
    sbom_name = st.session_state.sbom_name

    st.info(f"Loaded: {sbom_name}")

    if st.button("Rank Vulnerabilities", type="primary"):
        with st.spinner("Running pipeline..."):
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    weights_file = Path(tmpdir) / "weights.json"
                    weights_file.write_text(json.dumps({
                        "kev_boost": kev_boost,
                        "epss_weight": epss_weight,
                        "cvss_weight": cvss_weight,
                    }))

                    if offline_mode:
                        result = run_offline(
                            sbom_path,
                            weights_path=weights_file,
                        )
                    else:
                        result = run_live(
                            sbom_path,
                            weights_path=weights_file,
                        )

                    st.session_state.result = result
                    st.success("Pipeline complete!")

            except Exception as e:
                st.error(f"Pipeline failed: {str(e)}")
                import traceback
                st.error(traceback.format_exc())

    if "result" in st.session_state:
        result = st.session_state.result
        findings = result.findings

        st.markdown("---")
        st.subheader("Summary")

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Findings", len(findings))
        with col2:
            kev_count = sum(1 for f in findings if f.kev_flag)
            st.metric("CISA KEV (Active Exploit)", kev_count)
        with col3:
            high_epss = sum(1 for f in findings if (f.epss or 0) > 0.8)
            st.metric("High EPSS (>0.8)", high_epss)

        st.markdown("---")
        st.subheader("Ranked Findings")

        table_data = []
        for finding in findings:
            table_data.append(
                {
                    "CVE": finding.cve_id,
                    "Risk": f"{finding.score:.1f}",
                    "CVSS": f"{finding.cvss:.1f}" if finding.cvss else "—",
                    "EPSS": f"{finding.epss:.0%}",
                    "KEV": "Yes" if finding.kev_flag else "—",
                    "Component": finding.component.name,
                    "Reason": finding.reason,
                }
            )

        st.dataframe(
            table_data,
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("---")
        st.subheader("Export Results")

        export_data = {
            "summary": {
                "total_findings": len(findings),
                "kev_listed_count": sum(1 for f in findings if f.kev_flag),
            },
            "findings": [
                {
                    "cve": f.cve_id,
                    "risk_score": f.score,
                    "cvss": f.cvss,
                    "epss": f.epss,
                    "kev_listed": f.kev_flag,
                    "component": f.component.name,
                    "reason": f.reason,
                }
                for f in findings
            ],
        }

        col1, col2 = st.columns(2)

        with col1:
            json_str = json.dumps(export_data, indent=2)
            st.download_button(
                label="Download as JSON",
                data=json_str,
                file_name="triagesbom_ranked.json",
                mime="application/json",
            )

        with col2:
            csv_lines = ["CVE,Risk,CVSS,EPSS,KEV,Component,Reason"]
            for f in export_data["findings"]:
                csv_lines.append(
                    f'{f["cve"]},{f["risk_score"]:.1f},{f["cvss"] or ""},{f["epss"]:.0%},{f["kev_listed"]},{f["component"]},"{f["reason"]}"'
                )
            csv_data = "\n".join(csv_lines)
            st.download_button(
                label="Download as CSV",
                data=csv_data,
                file_name="triagesbom_ranked.csv",
                mime="text/csv",
            )

else:
    st.info("Upload a CycloneDX SBOM JSON file or load the sample to get started.")
