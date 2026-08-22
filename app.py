import json
from datetime import datetime

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
# CSS — dark SOC aesthetic (same palette/identity, tightened for an
# enterprise console feel). See README "UI notes" for the sidebar-toggle
# fix explanation.
# ---------------------------------------------------------------------------

st.markdown("""
<style>
.stApp{
    background:
        radial-gradient(circle at top left,#0D1B3D 0%,transparent 35%),
        radial-gradient(circle at top right,#071327 0%,transparent 30%),
        #050A18;
    color:#E7EEF9;
    font-family:'Segoe UI',sans-serif;
}
.block-container{ padding-top:1.1rem; padding-left:2rem; padding-right:2rem; max-width:1400px; }

/* --------------------------------------------------------------------
   HEADER / SIDEBAR TOGGLE — DO NOT hide [data-testid="stHeader"] or the
   bare <header> element. That element is where Streamlit renders the
   sidebar re-open control once the sidebar is collapsed; hiding it with
   visibility:hidden previously trapped users with no way back in. Instead
   we blend the header into the theme and only remove the decorative
   "Deploy" button and the hamburger/main menu, while explicitly forcing
   the expand/collapse controls to stay visible and on-brand.
   -------------------------------------------------------------------- */
[data-testid="stHeader"]{
    background:transparent;
    height:3rem;
}
#MainMenu{ visibility:hidden; }
[data-testid="stAppDeployButton"]{ display:none; }
[data-testid="stExpandSidebarButton"],
[data-testid="stSidebarCollapseButton"],
[data-testid="stSidebarCollapsedControl"],
[data-testid="collapsedControl"]{
    visibility:visible !important;
    opacity:1 !important;
    display:flex !important;
}
[data-testid="stExpandSidebarButton"] svg,
[data-testid="stSidebarCollapseButton"] svg,
[data-testid="stSidebarCollapsedControl"] svg,
[data-testid="collapsedControl"] svg{
    fill:#4EA8FF !important;
}

section[data-testid="stSidebar"]{ background:#050A18; border-right:1px solid #16365D; }
[data-testid="stSidebarContent"]{ padding-top:0.5rem; }

/* --------------------------------------------------------------------
   TYPOGRAPHY HIERARCHY
   -------------------------------------------------------------------- */
.main-title{
    font-size:30px; font-weight:800; line-height:1.15;
    background: linear-gradient(90deg, #FFFFFF, #4EA8FF);
    -webkit-background-clip:text; -webkit-text-fill-color:transparent;
    margin-bottom:0;
}
.sub-title{ font-size:13px; color:#7C9BC7; margin-bottom:2px; font-weight:500; }
.eyebrow{
    font-size:11px; font-weight:700; letter-spacing:.09em; text-transform:uppercase;
    color:#4EA8FF; margin:14px 0 2px 0;
}
.section-title{ font-size:19px; font-weight:700; color:#EAF2FF; margin:0 0 2px 0; }
.section-subtitle{ font-size:13px; color:#7C9BC7; margin-bottom:12px; }

/* --------------------------------------------------------------------
   METRIC CARDS — restrained, consistent height, subtle depth only
   -------------------------------------------------------------------- */
.metric-card{
    background:#0B1325; padding:16px 18px; border-radius:10px;
    border:1px solid #16365D;
}
.metric-label{
    font-size:11px; font-weight:700; letter-spacing:.06em; text-transform:uppercase;
    color:#7C9BC7; margin-bottom:6px;
}
.metric-value{ font-size:28px; font-weight:800; color:#F2F6FC; line-height:1; }

/* --------------------------------------------------------------------
   PANELS (chart cards, grouped content)
   -------------------------------------------------------------------- */
.panel{ background:#081122; padding:14px 16px; border-radius:10px; border:1px solid #16365D; }
[class*="st-key-panel-"]{ background:#081122; border:1px solid #16365D; border-radius:10px; padding:10px 14px 4px 14px; }

/* --------------------------------------------------------------------
   PILL / BADGE SYSTEM — replaces oversized inline colored text
   -------------------------------------------------------------------- */
.pill{
    display:inline-block; padding:2px 9px; border-radius:999px;
    font-size:11px; font-weight:700; letter-spacing:.02em; line-height:1.7;
    white-space:nowrap;
}
.pill-critical{ background:rgba(255,60,90,.14); color:#FF8092; border:1px solid rgba(255,60,90,.35); }
.pill-medium{ background:rgba(255,176,32,.14); color:#FFC55C; border:1px solid rgba(255,176,32,.35); }
.pill-low{ background:rgba(51,209,122,.14); color:#5BE39B; border:1px solid rgba(51,209,122,.35); }
.pill-ok{ background:rgba(51,209,122,.14); color:#5BE39B; border:1px solid rgba(51,209,122,.35); }
.pill-warn{ background:rgba(255,176,32,.14); color:#FFC55C; border:1px solid rgba(255,176,32,.35); }
.pill-bad{ background:rgba(255,60,90,.14); color:#FF8092; border:1px solid rgba(255,60,90,.35); }
.pill-muted{ background:rgba(124,155,199,.12); color:#9FC3F2; border:1px solid rgba(124,155,199,.28); }

/* --------------------------------------------------------------------
   RECENT INVESTIGATIONS — compact row list, not cards
   -------------------------------------------------------------------- */
.row-header{
    font-size:11px; font-weight:700; letter-spacing:.05em; text-transform:uppercase;
    color:#5B7BA6; padding:4px 4px 8px 4px; border-bottom:1px solid #16365D;
}
.row-cell{ font-size:13px; padding:7px 4px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.row-cell-strong{ color:#EAF2FF; font-weight:600; }
.row-cell-muted{ color:#8DA9CE; }
div[class*="st-key-row-"]{ border-bottom:1px solid #0F2038; }
div[class*="st-key-row-"]:hover{ background:rgba(78,168,255,.035); }
div[class*="st-key-row-"] button{
    padding:2px 10px !important; font-size:12px !important; min-height:26px !important;
    background:transparent !important; border:1px solid #2B5C9A !important; color:#8FC1FF !important;
}

/* --------------------------------------------------------------------
   ALERT / FINDING BOXES (Log Analysis)
   -------------------------------------------------------------------- */
.alert-box{
    background:#081122; padding:10px 12px; border-left:3px solid #FF3C5A;
    margin-bottom:6px; border-radius:6px; font-size:13px; color:#C9D9F2;
}
.alert-box code{ color:#9FC3F2; font-size:12px; }
.alert-box i{ color:#7C9BC7; font-size:12px; }

/* --------------------------------------------------------------------
   STATUS STRIP (provider/system status, compact single line, wraps)
   -------------------------------------------------------------------- */
.status-strip{ display:flex; flex-wrap:wrap; gap:18px; align-items:center; }
.status-strip-item{ font-size:12px; color:#8DA9CE; display:flex; align-items:center; gap:6px; }
.status-strip-label{ color:#5B7BA6; }

.footer{ text-align:center; color:#4C6690; margin-top:36px; font-size:12px; }

/* --------------------------------------------------------------------
   FORM CONTROLS
   -------------------------------------------------------------------- */
.stTextInput > div > div > input{
    background:#0B1325!important; color:#E7EEF9!important;
    border:1px solid #2B5C9A!important; border-radius:8px!important; padding:9px 12px!important;
}
[data-testid="stFileUploader"]{ background:#0B1325!important; border:1px solid #2B5C9A!important; border-radius:10px!important; padding:8px!important; }
[data-testid="stFileUploader"] *{ color:#E7EEF9!important; }
[data-testid="stFileUploaderDropzone"]{ background:#0B1325!important; border:1px dashed #4EA8FF!important; border-radius:8px!important; }
[data-testid="stFileUploaderDropzone"] *{ background:transparent!important; color:#E7EEF9!important; }

[data-testid="stMetricValue"]{ color:#F2F6FC; }
[data-testid="stMetricLabel"]{ color:#7C9BC7; }

/* --------------------------------------------------------------------
   RESPONSIVE
   -------------------------------------------------------------------- */
@media (max-width: 640px){
    .block-container{ padding-left:0.9rem; padding-right:0.9rem; }
    .main-title{ font-size:23px; }
    .metric-value{ font-size:22px; }
    .row-cell{ font-size:12px; }
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="main-title">🛡 ThreatScope</div>
<div class="sub-title">Threat Intelligence &amp; SOC Investigation Platform</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# NAVIGATION — session-state-backed so in-page actions (e.g. "View →" on
# Recent Investigations) can switch pages programmatically, in addition to
# the sidebar. The widget itself is still a plain st.sidebar.radio.
# ---------------------------------------------------------------------------

PAGE_DASHBOARD = "Dashboard"
PAGE_IOC = "IOC Investigation"
PAGE_LOGS = "Log Analysis"
PAGE_FILES = "File Analysis"
PAGE_MITRE = "MITRE ATT&CK"
PAGE_HISTORY = "Investigation History"
PAGE_SETTINGS = "Settings / Provider Status"
PAGES = [PAGE_DASHBOARD, PAGE_IOC, PAGE_LOGS, PAGE_FILES, PAGE_MITRE, PAGE_HISTORY, PAGE_SETTINGS]

if "nav_page" not in st.session_state:
    st.session_state.nav_page = PAGE_DASHBOARD


def go_to(target_page: str):
    st.session_state.nav_page = target_page


page = st.sidebar.radio("Navigate", PAGES, key="nav_page")

st.markdown(f'<div class="eyebrow">{page}</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# SHARED UI HELPERS (presentation only — no investigation logic here)
# ---------------------------------------------------------------------------

def section_header(title: str, subtitle: str = ""):
    st.markdown(f'<div class="section-title">{title}</div>', unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div class="section-subtitle">{subtitle}</div>', unsafe_allow_html=True)


def pill(text: str, kind: str) -> str:
    return f'<span class="pill pill-{kind}">{text}</span>'


_SEVERITY_KIND = {"Critical": "critical", "High": "critical", "Medium": "medium", "Low": "low"}


def severity_pill(severity: str) -> str:
    return pill(severity or "Unknown", _SEVERITY_KIND.get(severity, "muted"))


_CLASS_KIND = {"Malicious": "critical", "Suspicious": "medium", "Clean": "low"}


def classification_pill(classification: str) -> str:
    return pill(classification or "Unknown", _CLASS_KIND.get(classification, "muted"))


_PROVIDER_STATUS_KIND = {
    api_client.STATUS_OK: ("ok", "Connected"),
    api_client.STATUS_NOT_FOUND: ("ok", "Connected"),
    api_client.STATUS_NOT_CONFIGURED: ("muted", "Not configured"),
    api_client.STATUS_INVALID_KEY: ("bad", "Invalid key"),
    api_client.STATUS_RATE_LIMITED: ("warn", "Rate limited"),
}


def provider_status_pill(status: str) -> str:
    kind, label = _PROVIDER_STATUS_KIND.get(status, ("bad", "Error"))
    return pill(label, kind)


_RESULT_STATUS_KIND = {
    ioc_analysis.RESULT_VALID: "ok",
    ioc_analysis.RESULT_NO_DATA: "muted",
    ioc_analysis.RESULT_INVALID_IOC: "bad",
    ioc_analysis.RESULT_PROVIDERS_UNAVAILABLE: "warn",
}


def result_status_pill(status: str) -> str:
    return pill(status, _RESULT_STATUS_KIND.get(status, "muted"))


def cfg_pill(configured: bool, optional: bool = False) -> str:
    if configured:
        return pill("Connected", "ok")
    return pill("Optional · Not configured", "muted") if optional else pill("Not configured", "warn")


def format_timestamp(raw: str) -> str:
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%b %d, %H:%M")
    except (ValueError, AttributeError):
        return raw or "—"


def summarize_sources(raw_json) -> str:
    if not raw_json:
        return "—"
    try:
        data = json.loads(raw_json)
    except (TypeError, ValueError):
        return "—"
    if not data:
        return "—"
    total = len(data)
    ok = sum(1 for v in data.values() if v in (api_client.STATUS_OK, api_client.STATUS_NOT_FOUND))
    return f"{ok}/{total}"


# Palette used consistently across every chart, matching the existing
# severity/risk colors already used for badges elsewhere in the app.
CHART_COLOR_MAP = {
    "Malicious": "#FF3C5A", "Suspicious": "#FFB020", "Clean": "#33D17A", "Unknown": "#5B7BA6",
    "Critical": "#FF3C5A", "High": "#FF6B4A", "Medium": "#FFB020", "Low": "#33D17A",
    "Brute Force": "#FF6B4A", "Malware Indicator": "#FF3C5A", "Port Scan": "#FFB020",
    "Privilege Escalation": "#4EA8FF",
}
CHART_FALLBACK_COLORS = ["#4EA8FF", "#5B7BA6", "#33D17A", "#FFB020", "#FF6B4A", "#FF3C5A"]


def render_bar_chart(df: pd.DataFrame, x_col: str, y_col: str, height: int = 240):
    """Slim, enterprise-style bar chart using the ThreatScope palette."""
    fig = px.bar(
        df, x=x_col, y=y_col, color=x_col,
        color_discrete_map=CHART_COLOR_MAP,
        color_discrete_sequence=CHART_FALLBACK_COLORS,
    )
    fig.update_traces(
        marker_line_width=0,
        hovertemplate=f"<b>%{{x}}</b><br>{y_col}: %{{y}}<extra></extra>",
    )
    fig.update_layout(
        showlegend=False,
        height=height,
        margin=dict(l=6, r=6, t=6, b=6),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        bargap=0.55,
        font=dict(color="#B9CBE8", size=12, family="Segoe UI"),
        xaxis=dict(showgrid=False, tickfont=dict(color="#9FC3F2", size=11), title=None,
                   linecolor="#16365D", showline=True),
        yaxis=dict(showgrid=True, gridcolor="rgba(22,54,93,.55)", zeroline=False,
                   tickfont=dict(color="#9FC3F2", size=11), title=None),
        hoverlabel=dict(bgcolor="#0B1325", font_color="#E7EEF9", bordercolor="#2B5C9A"),
    )
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})


def render_donut_chart(df: pd.DataFrame, names_col: str, values_col: str, height: int = 240):
    """Balanced donut chart with severity-consistent colors and outside legend."""
    fig = px.pie(
        df, names=names_col, values=values_col, hole=0.62, color=names_col,
        color_discrete_map=CHART_COLOR_MAP,
        color_discrete_sequence=CHART_FALLBACK_COLORS,
    )
    fig.update_traces(
        textinfo="percent",
        textfont=dict(color="#081122", size=12, family="Segoe UI"),
        marker=dict(line=dict(color="#081122", width=2)),
        hovertemplate=f"<b>%{{label}}</b><br>%{{value}} (%{{percent}})<extra></extra>",
    )
    fig.update_layout(
        height=height,
        margin=dict(l=6, r=6, t=6, b=6),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.16, x=0.5, xanchor="center",
                    font=dict(color="#B9CBE8", size=11)),
        hoverlabel=dict(bgcolor="#0B1325", font_color="#E7EEF9", bordercolor="#2B5C9A"),
    )
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})


def render_recent_investigations(rows):
    if not rows:
        st.info("No investigations recorded yet. Run an IOC, log, or file analysis to populate this list.")
        return

    col_spec = [1.1, 0.9, 2.6, 1.15, 1.0, 0.9, 0.9]
    headers = ["Time", "Kind", "Investigation", "Classification", "Severity", "Sources", ""]
    header_cols = st.columns(col_spec)
    for col, label in zip(header_cols, headers):
        col.markdown(f'<div class="row-header">{label}</div>', unsafe_allow_html=True)

    for r in rows:
        with st.container(key=f"row-{r['id']}", border=False):
            c1, c2, c3, c4, c5, c6, c7 = st.columns(col_spec)
            c1.markdown(f'<div class="row-cell row-cell-muted">{format_timestamp(r["timestamp"])}</div>', unsafe_allow_html=True)
            c2.markdown(f'<div class="row-cell row-cell-muted">{r["kind"]}</div>', unsafe_allow_html=True)
            c3.markdown(f'<div class="row-cell row-cell-strong">{r["ioc_value"] or "(upload)"}</div>', unsafe_allow_html=True)
            c4.markdown(f'<div class="row-cell">{classification_pill(r["classification"])}</div>', unsafe_allow_html=True)
            c5.markdown(f'<div class="row-cell">{severity_pill(r["severity"])}</div>', unsafe_allow_html=True)
            c6.markdown(f'<div class="row-cell row-cell-muted">{summarize_sources(r["provider_summary"])}</div>', unsafe_allow_html=True)
            c7.button("View →", key=f"view_{r['id']}", on_click=go_to, args=(PAGE_HISTORY,), width="stretch")


def render_provider_status_strip():
    yara_status, _ = yara_engine.engine_status()
    items = [
        ("VirusTotal", cfg_pill(PROVIDERS.virustotal_configured)),
        ("AbuseIPDB", cfg_pill(PROVIDERS.abuseipdb_configured)),
        ("AlienVault OTX", cfg_pill(PROVIDERS.otx_configured, optional=True)),
        ("YARA engine", pill("Ready", "ok") if yara_status == yara_engine.STATUS_READY else pill("Unavailable", "muted")),
    ]
    parts = "".join(
        f'<div class="status-strip-item"><span class="status-strip-label">{label}</span> {badge}</div>'
        for label, badge in items
    )
    st.markdown(f'<div class="status-strip">{parts}</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------------------------

if page == PAGE_DASHBOARD:
    counts = db.fetch_dashboard_counts()

    section_header("Key SOC Metrics")
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

    by_class = counts["by_classification"]
    if by_class:
        section_header("Primary Analytics", "Investigation outcomes recorded so far, by classification.")
        df = pd.DataFrame({"Classification": list(by_class.keys()), "Count": list(by_class.values())})
        left, right = st.columns([1.6, 1])
        with left:
            with st.container(key="panel-bar", border=True):
                render_bar_chart(df, "Classification", "Count")
        with right:
            with st.container(key="panel-donut", border=True):
                render_donut_chart(df, "Classification", "Count")
    else:
        section_header("Primary Analytics")
        st.info("No investigations recorded yet. Run an IOC, log, or file analysis to populate the dashboard.")

    section_header("Recent Investigations", "The 10 most recently recorded investigations, newest first.")
    render_recent_investigations(db.fetch_recent(limit=10))

    section_header("Supporting Threat Intelligence", "Live provider and engine status.")
    render_provider_status_strip()


# ---------------------------------------------------------------------------
# IOC INVESTIGATION
# ---------------------------------------------------------------------------

elif page == PAGE_IOC:
    section_header("🔎 IOC Investigation", "Supports IPv4 addresses, domains, http(s) URLs, and MD5/SHA1/SHA256 file hashes.")

    search_value = st.text_input("Search IP / Domain / URL / File Hash", label_visibility="collapsed",
                                  placeholder="Search IP / Domain / URL / File Hash")

    if search_value:
        with st.spinner("Querying threat-intelligence providers..."):
            result = ioc_analysis.investigate(search_value, PROVIDERS)

        st.markdown(
            f"**IOC Type:** {result.ioc_type} &nbsp;&nbsp; "
            f"**Status:** {result_status_pill(result.result_status)}",
            unsafe_allow_html=True,
        )

        if result.result_status == ioc_analysis.RESULT_INVALID_IOC:
            st.error(result.explanation)
        else:
            with st.container(key="panel-ioc-result", border=True):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(
                        f"**Classification:** {classification_pill(result.classification)}  \n"
                        f"**Severity:** {severity_pill(result.severity)}  \n"
                        f"**Confidence:** {result.confidence}  \n"
                        f"**Country:** {result.country or 'Unknown'}",
                        unsafe_allow_html=True,
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
                    st.markdown(f"- {provider}: {provider_status_pill(status)} — {msg}", unsafe_allow_html=True)

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
    section_header("📂 Log Analysis", "Supports .txt, .log, .csv, and .json (array or JSON-lines).")

    uploaded_file = st.file_uploader("Upload Threat Logs", type=["txt", "csv", "log", "json"],
                                      label_visibility="collapsed")

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
                with st.container(key="panel-log-categories", border=True):
                    render_bar_chart(cat_df, "Category", "Count", height=220)

                st.markdown("**Findings**")
                for finding in result.findings[:200]:
                    techniques = mitre_mapper.map_log_finding(finding.category)
                    mitre_txt = ", ".join(f"{t.technique_id} {t.technique_name}" for t in techniques) or "No defensible MITRE mapping"
                    st.markdown(
                        f'<div class="alert-box">Line {finding.line_number} '
                        f'{severity_pill(finding.severity)} <b>{finding.category}</b> '
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
    section_header("🧬 File Analysis", "Local hashing + heuristics, optional YARA matching, optional VirusTotal hash reputation.")

    uploaded = st.file_uploader("Upload a file to analyze", label_visibility="collapsed")

    if uploaded:
        file_bytes = uploaded.read()
        result = malware_scan.analyze_file(uploaded.name, file_bytes, PROVIDERS)

        status_kind = {
            malware_scan.STATUS_MALICIOUS: "critical",
            malware_scan.STATUS_SUSPICIOUS: "medium",
            malware_scan.STATUS_LOW_RISK: "low",
            malware_scan.STATUS_UNKNOWN: "muted",
            malware_scan.STATUS_FAILED: "bad",
        }.get(result.status, "muted")

        with st.container(key="panel-file-result", border=True):
            st.markdown(f"**Status:** {pill(result.status, status_kind)}", unsafe_allow_html=True)
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
                st.markdown(f"**VirusTotal:** {provider_status_pill(result.vt_status)}", unsafe_allow_html=True)

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
    section_header(
        "🗺 MITRE ATT&CK Mapping",
        "ThreatScope maps a finding to a technique only where there is a defensible relationship. "
        "This is a reference table of every mapping currently defined — not every finding will match one.",
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

    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)


# ---------------------------------------------------------------------------
# INVESTIGATION HISTORY
# ---------------------------------------------------------------------------

elif page == PAGE_HISTORY:
    section_header("🕘 Investigation History", "Persisted in a local SQLite database — survives a page refresh, not reset per session.")

    rows = db.fetch_recent(limit=200)
    if not rows:
        st.info("No investigations recorded yet.")
    else:
        hist_df = pd.DataFrame([dict(r) for r in rows])
        st.dataframe(
            hist_df[["timestamp", "kind", "ioc_value", "ioc_type", "classification", "severity", "result_status"]],
            width="stretch", hide_index=True,
        )


# ---------------------------------------------------------------------------
# SETTINGS / PROVIDER STATUS
# ---------------------------------------------------------------------------

elif page == PAGE_SETTINGS:
    section_header("⚙️ Settings / Provider Status", "Configuration status only — actual key values are never displayed.")

    st.markdown(f"**VirusTotal:** {cfg_pill(PROVIDERS.virustotal_configured)}", unsafe_allow_html=True)
    st.markdown(f"**AbuseIPDB:** {cfg_pill(PROVIDERS.abuseipdb_configured)}", unsafe_allow_html=True)
    st.markdown(f"**AlienVault OTX:** {cfg_pill(PROVIDERS.otx_configured, optional=True)}", unsafe_allow_html=True)

    yara_status, yara_message = yara_engine.engine_status()
    yara_badge = pill("Ready", "ok") if yara_status == yara_engine.STATUS_READY else pill("Unavailable", "muted")
    st.markdown(f"**YARA engine:** {yara_badge} — {yara_message}", unsafe_allow_html=True)

    st.markdown(f"**Machine learning component:** {pill('Not integrated', 'muted')}", unsafe_allow_html=True)
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
