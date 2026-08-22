import streamlit as st
import pandas as pd
import plotly.express as px

import api_client
import db
import ioc_analysis
import log_parser
import malware_scan
import mitre_mapper
import yara_engine
from config import load_provider_config

# ---------------------------------------------------------------------------
# PAGE CONFIG + DB INIT
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="ThreatScope",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

db.init_db()
PROVIDERS = load_provider_config()

# ---------------------------------------------------------------------------
# CSS — dark SOC aesthetic (kept from the original identity, cleaned up)
# ---------------------------------------------------------------------------

st.markdown("""
<style>
.stApp{
    background:
        radial-gradient(circle at top left,#0D1B3D 0%,transparent 35%),
        radial-gradient(circle at top right,#071327 0%,transparent 30%),
        #050A18;
    color:white;
    font-family:'Segoe UI';
}
header{ visibility:hidden; }
#MainMenu{ visibility:hidden; }
.block-container{ padding-top:1.5rem; padding-left:2rem; padding-right:2rem; }

.main-title{
    font-size:46px; font-weight:800;
    background: linear-gradient(90deg, white, #4EA8FF);
    -webkit-background-clip:text; -webkit-text-fill-color:transparent;
    margin-bottom:0;
}
.sub-title{ font-size:18px; color:#67B8FF; margin-bottom:20px; }

.metric-card{
    background:#0B1325; padding:22px; border-radius:16px;
    border:1px solid #16365D; box-shadow:0 0 20px rgba(0,150,255,.10);
}
.metric-value{ font-size:36px; font-weight:800; color:white; }
.metric-label{ font-size:14px; color:#8FB6E8; }

.alert-box{
    background:#081122; padding:12px; border-left:4px solid #FF3C5A;
    margin-bottom:8px; border-radius:10px; font-size:14px;
}
.panel{
    background:#081122; padding:18px; border-radius:16px; border:1px solid #16365D;
}
.status-ok{ color:#33D17A; font-weight:700; }
.status-warn{ color:#FFB020; font-weight:700; }
.status-bad{ color:#FF3C5A; font-weight:700; }
.status-muted{ color:#8FB6E8; font-weight:600; }

.footer{ text-align:center; color:#7DBFFF; margin-top:40px; font-size:13px; }

.stTextInput > div > div > input{
    background:#0B1325!important; color:white!important;
    border:1px solid #2B5C9A!important; border-radius:12px!important; padding:10px!important;
}
[data-testid="stFileUploader"]{ background:#0B1325!important; border:1px solid #2B5C9A!important; border-radius:14px!important; padding:10px!important; }
[data-testid="stFileUploader"] *{ color:white!important; }
[data-testid="stFileUploaderDropzone"]{ background:#0B1325!important; border:1px dashed #4EA8FF!important; border-radius:12px!important; }
[data-testid="stFileUploaderDropzone"] *{ background:transparent!important; color:white!important; }

section[data-testid="stSidebar"]{ background:#050A18; border-right:1px solid #16365D; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="main-title">🛡 ThreatScope</div>
<div class="sub-title">Threat Intelligence &amp; SOC Investigation Platform</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# NAVIGATION
# ---------------------------------------------------------------------------

PAGE_DASHBOARD = "Dashboard"
PAGE_IOC = "IOC Investigation"
PAGE_LOGS = "Log Analysis"
PAGE_FILES = "File Analysis"
PAGE_MITRE = "MITRE ATT&CK"
PAGE_HISTORY = "Investigation History"
PAGE_SETTINGS = "Settings / Provider Status"

page = st.sidebar.radio(
    "Navigate",
    [PAGE_DASHBOARD, PAGE_IOC, PAGE_LOGS, PAGE_FILES, PAGE_MITRE, PAGE_HISTORY, PAGE_SETTINGS],
)


def severity_badge(severity: str) -> str:
    cls = {
        "Critical": "status-bad", "High": "status-bad",
        "Medium": "status-warn", "Low": "status-ok",
    }.get(severity, "status-muted")
    return f'<span class="{cls}">{severity}</span>'


def provider_status_badge(status: str) -> str:
    if status == api_client.STATUS_OK or status == api_client.STATUS_NOT_FOUND:
        return f'<span class="status-ok">Connected</span>'
    if status == api_client.STATUS_NOT_CONFIGURED:
        return f'<span class="status-muted">Not configured</span>'
    if status == api_client.STATUS_INVALID_KEY:
        return f'<span class="status-bad">Invalid key</span>'
    if status == api_client.STATUS_RATE_LIMITED:
        return f'<span class="status-warn">Rate limited</span>'
    return f'<span class="status-bad">Error</span>'


# ---------------------------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------------------------

if page == PAGE_DASHBOARD:
    counts = db.fetch_dashboard_counts()

    c1, c2, c3, c4 = st.columns(4)
    cards = [
        ("Total Investigations", counts["total"]),
        ("Critical Findings", counts["critical"]),
        ("High-Severity Findings", counts["high"]),
        ("Suspicious / Malicious IOCs", counts["suspicious"]),
    ]
    for col, (label, value) in zip([c1, c2, c3, c4], cards):
        with col:
            st.markdown(
                f'<div class="metric-card"><div class="metric-label">{label}</div>'
                f'<div class="metric-value">{value}</div></div>',
                unsafe_allow_html=True,
            )

    st.markdown("&nbsp;", unsafe_allow_html=True)

    by_class = counts["by_classification"]
    if by_class:
        df = pd.DataFrame({"Classification": list(by_class.keys()), "Count": list(by_class.values())})
        left, right = st.columns([2, 1])
        with left:
            fig = px.bar(df, x="Classification", y="Count", template="plotly_dark")
            fig.update_layout(paper_bgcolor="#081122", plot_bgcolor="#081122", font_color="white")
            st.plotly_chart(fig, use_container_width=True)
        with right:
            pie = px.pie(df, names="Classification", values="Count", hole=.55, template="plotly_dark")
            pie.update_layout(paper_bgcolor="#081122", plot_bgcolor="#081122", font=dict(color="white"))
            st.plotly_chart(pie, use_container_width=True)
    else:
        st.info("No investigations recorded yet. Run an IOC, log, or file analysis to populate the dashboard.")

    st.markdown('<div class="panel"><h3>Recent Investigations</h3>', unsafe_allow_html=True)
    rows = db.fetch_recent(limit=10)
    if rows:
        for r in rows:
            st.markdown(
                f"`{r['timestamp']}` — **{r['kind']}** — "
                f"{r['ioc_value'] or '(file/log upload)'} — "
                f"{r['classification'] or '—'} / {severity_badge(r['severity'] or 'Unknown')} "
                f"— *{r['result_status']}*",
                unsafe_allow_html=True,
            )
    else:
        st.write("Nothing recorded yet.")
    st.markdown("</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# IOC INVESTIGATION
# ---------------------------------------------------------------------------

elif page == PAGE_IOC:
    st.markdown("## 🔎 IOC Investigation")
    st.caption("Supports IPv4 addresses, domains, http(s) URLs, and MD5/SHA1/SHA256 file hashes.")

    search_value = st.text_input("Search IP / Domain / URL / File Hash")

    if search_value:
        with st.spinner("Querying threat-intelligence providers..."):
            result = ioc_analysis.investigate(search_value, PROVIDERS)

        status_class = {
            ioc_analysis.RESULT_VALID: "status-ok",
            ioc_analysis.RESULT_NO_DATA: "status-muted",
            ioc_analysis.RESULT_INVALID_IOC: "status-bad",
            ioc_analysis.RESULT_PROVIDERS_UNAVAILABLE: "status-warn",
        }.get(result.result_status, "status-muted")

        st.markdown(
            f"**IOC Type:** {result.ioc_type} &nbsp;&nbsp; "
            f"**Status:** <span class='{status_class}'>{result.result_status}</span>",
            unsafe_allow_html=True,
        )

        if result.result_status == ioc_analysis.RESULT_INVALID_IOC:
            st.error(result.explanation)
        else:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(
                    f"""**Classification:** {result.classification}
**Severity:** {result.severity}
**Confidence:** {result.confidence}
**Country:** {result.country or 'Unknown'}"""
                )
            with col2:
                st.markdown(
                    f"""**VirusTotal malicious engines:** {result.vt_malicious_count if result.vt_malicious_count is not None else '—'}
**AbuseIPDB confidence score:** {result.abuse_score if result.abuse_score is not None else '—'}"""
                )

            if result.explanation:
                st.info(result.explanation)

            st.markdown("**Provider status**")
            for provider, status in result.provider_statuses.items():
                msg = result.provider_messages.get(provider, "")
                st.markdown(f"- {provider}: {provider_status_badge(status)} — {msg}", unsafe_allow_html=True)

            if result.mitre:
                st.markdown("**MITRE ATT&CK mapping**")
                for t in result.mitre:
                    st.markdown(f"- `{t.technique_id}` **{t.technique_name}** ({t.tactic}) — {t.explanation}")

        db.record_investigation(
            kind="IOC",
            ioc_value=result.ioc_value,
            ioc_type=result.ioc_type,
            classification=result.classification if result.result_status == ioc_analysis.RESULT_VALID else None,
            severity=result.severity if result.result_status == ioc_analysis.RESULT_VALID else None,
            result_status=result.result_status,
            provider_summary=result.provider_statuses,
            findings_summary={"mitre": [t.technique_id for t in result.mitre]},
        )


# ---------------------------------------------------------------------------
# LOG ANALYSIS
# ---------------------------------------------------------------------------

elif page == PAGE_LOGS:
    st.markdown("## 📂 Log Analysis")
    st.caption("Supports .txt, .log, .csv, and .json (array or JSON-lines).")

    uploaded_file = st.file_uploader("Upload Threat Logs", type=["txt", "csv", "log", "json"])

    if uploaded_file:
        raw = uploaded_file.read()
        result = log_parser.parse_log(uploaded_file.name, raw)

        if not result.parse_ok:
            st.error(f"Could not analyze this file: {result.parse_message}")
        else:
            c1, c2, c3 = st.columns(3)
            c1.metric("Total Events", result.total_events)
            c2.metric("Suspicious Events", result.suspicious_events)
            c3.metric("Extracted IOCs", len(result.extracted_iocs))

            if result.category_counts:
                st.markdown("**Detected categories**")
                cat_df = pd.DataFrame(
                    {"Category": list(result.category_counts.keys()), "Count": list(result.category_counts.values())}
                )
                fig = px.bar(cat_df, x="Category", y="Count", template="plotly_dark")
                fig.update_layout(paper_bgcolor="#081122", plot_bgcolor="#081122", font_color="white")
                st.plotly_chart(fig, use_container_width=True)

                st.markdown("**Findings**")
                for finding in result.findings[:200]:
                    techniques = mitre_mapper.map_log_finding(finding.category)
                    mitre_txt = ", ".join(f"{t.technique_id} {t.technique_name}" for t in techniques) or "No defensible MITRE mapping"
                    st.markdown(
                        f'<div class="alert-box">Line {finding.line_number} '
                        f'[{severity_badge(finding.severity)}] <b>{finding.category}</b> '
                        f'{("at " + finding.timestamp) if finding.timestamp else ""}'
                        f'<br><code>{finding.raw_line}</code>'
                        f'<br><i>MITRE: {mitre_txt}</i></div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.success("No suspicious patterns detected in this file.")

            if result.extracted_iocs:
                st.markdown("**Extracted candidate IOCs (not yet enriched — investigate individually on the IOC page)**")
                st.write(sorted(result.extracted_iocs))

            top_severity = None
            if result.findings:
                sev_rank = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
                top_severity = max((f.severity for f in result.findings), key=lambda s: sev_rank.get(s, 0))

            db.record_investigation(
                kind="LOG",
                ioc_value=uploaded_file.name,
                classification=("Suspicious" if result.suspicious_events else "Clean"),
                severity=top_severity,
                result_status="VALID RESULT" if result.parse_ok else "PARSE FAILED",
                findings_summary={"categories": result.category_counts, "total_events": result.total_events},
            )


# ---------------------------------------------------------------------------
# FILE ANALYSIS
# ---------------------------------------------------------------------------

elif page == PAGE_FILES:
    st.markdown("## 🧬 File Analysis")
    st.caption("Local hashing + heuristics, optional YARA matching, optional VirusTotal hash reputation.")

    uploaded = st.file_uploader("Upload a file to analyze")

    if uploaded:
        file_bytes = uploaded.read()
        result = malware_scan.analyze_file(uploaded.name, file_bytes, PROVIDERS)

        status_class = {
            malware_scan.STATUS_MALICIOUS: "status-bad",
            malware_scan.STATUS_SUSPICIOUS: "status-warn",
            malware_scan.STATUS_LOW_RISK: "status-ok",
            malware_scan.STATUS_UNKNOWN: "status-muted",
            malware_scan.STATUS_FAILED: "status-bad",
        }.get(result.status, "status-muted")

        st.markdown(f"**Status:** <span class='{status_class}'>{result.status}</span>", unsafe_allow_html=True)
        st.markdown(
            f"""**File:** {result.filename}
**Size:** {result.size_bytes} bytes
**SHA-256:** `{result.sha256}`
**MD5:** `{result.md5}`"""
        )

        if result.local_indicators:
            st.markdown("**Local indicators**")
            for ind in result.local_indicators:
                st.markdown(f"- {ind}")

        st.markdown(f"**YARA engine:** {result.yara_status}")
        if result.vt_malicious_count is not None:
            st.markdown(f"**VirusTotal:** {result.vt_malicious_count}/{result.vt_total_engines} engines flagged this hash malicious.")
        else:
            st.markdown(f"**VirusTotal:** {provider_status_badge(result.vt_status)}", unsafe_allow_html=True)

        st.caption(result.notes)

        db.record_investigation(
            kind="FILE",
            ioc_value=result.filename,
            ioc_type="SHA256 Hash",
            classification=result.status,
            severity=None,
            result_status=result.status,
            provider_summary={"virustotal": result.vt_status, "yara": result.yara_status},
        )


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------

elif page == PAGE_MITRE:
    st.markdown("## 🗺 MITRE ATT&CK Mapping")
    st.caption(
        "ThreatScope maps a finding to a technique only where there is a defensible relationship. "
        "This is a reference table of every mapping currently defined — not every finding will match one."
    )

    rows = []
    for category, techniques in mitre_mapper._LOG_CATEGORY_MAP.items():
        for t in techniques:
            rows.append({"Source": f"Log finding: {category}", "Technique": f"{t.technique_id} {t.technique_name}",
                         "Tactic": t.tactic, "Rationale": t.explanation})
    for (ioc_type, classification), techniques in mitre_mapper._IOC_CLASSIFICATION_MAP.items():
        for t in techniques:
            rows.append({"Source": f"IOC: {ioc_type} ({classification})", "Technique": f"{t.technique_id} {t.technique_name}",
                         "Tactic": t.tactic, "Rationale": t.explanation})

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# INVESTIGATION HISTORY
# ---------------------------------------------------------------------------

elif page == PAGE_HISTORY:
    st.markdown("## 🕘 Investigation History")
    st.caption("Persisted in a local SQLite database — survives a page refresh, not reset per session.")

    rows = db.fetch_recent(limit=200)
    if not rows:
        st.info("No investigations recorded yet.")
    else:
        hist_df = pd.DataFrame([dict(r) for r in rows])
        st.dataframe(
            hist_df[["timestamp", "kind", "ioc_value", "ioc_type", "classification", "severity", "result_status"]],
            use_container_width=True, hide_index=True,
        )


# ---------------------------------------------------------------------------
# SETTINGS / PROVIDER STATUS
# ---------------------------------------------------------------------------

elif page == PAGE_SETTINGS:
    st.markdown("## ⚙️ Settings / Provider Status")
    st.caption("Configuration status only — actual key values are never displayed.")

    def cfg_badge(configured: bool, optional: bool = False) -> str:
        if configured:
            return '<span class="status-ok">Connected</span>'
        return '<span class="status-muted">Optional, not configured</span>' if optional else '<span class="status-warn">Not configured</span>'

    st.markdown(f"**VirusTotal:** {cfg_badge(PROVIDERS.virustotal_configured)}", unsafe_allow_html=True)
    st.markdown(f"**AbuseIPDB:** {cfg_badge(PROVIDERS.abuseipdb_configured)}", unsafe_allow_html=True)
    st.markdown(f"**AlienVault OTX:** {cfg_badge(PROVIDERS.otx_configured, optional=True)}", unsafe_allow_html=True)

    yara_status, yara_message = yara_engine.engine_status()
    yara_badge = '<span class="status-ok">Ready</span>' if yara_status == yara_engine.STATUS_READY else '<span class="status-muted">Unavailable</span>'
    st.markdown(f"**YARA engine:** {yara_badge} — {yara_message}", unsafe_allow_html=True)

    st.markdown("**Machine learning component:** <span class='status-muted'>Not integrated</span>", unsafe_allow_html=True)
    st.caption(
        "models/model.pkl expects 78 CICFlowMeter network-flow features extracted from raw packet "
        "captures, which nothing in this app produces from an IOC, log, or file upload. See "
        "train_model.py's module docstring and the README for the full explanation. It is kept in "
        "the repo as a documented, reproducible artifact, not a live feature."
    )

    st.markdown("---")
    st.caption(
        "Credentials are loaded from Streamlit Cloud Secrets in production, or a local, git-ignored "
        ".env file during development. See README for setup."
    )


# ---------------------------------------------------------------------------
# FOOTER
# ---------------------------------------------------------------------------

st.markdown(
    '<div class="footer">Engineered by Olawatosin Deborah Ajinomisan</div>',
    unsafe_allow_html=True,
)
