<<<<<<< HEAD
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------

st.set_page_config(
    page_title="ThreatScope",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------
# CUSTOM CSS
# ---------------------------------------------------

st.markdown("""
<style>

/* MAIN APP /
.stApp {
    background: #F3F4F6;
    color: #111827;
    font-family: 'Segoe UI', sans-serif;
}

/ REMOVE STREAMLIT PADDING ISSUES /
.block-container {
    padding-top: 2rem;
    padding-left: 3rem;
    padding-right: 3rem;
    max-width: 100%;
}

/ SIDEBAR /
section[data-testid="stSidebar"] {
    background: #FFFFFF;
    border-right: 1px solid #E5E7EB;
    width: 320px !important;
}

/ SIDEBAR TEXT /
section[data-testid="stSidebar"] * {
    color: #111827 !important;
    font-size: 16px !important;
}

/ TITLES /
.main-title {
    font-size: 42px;
    font-weight: 800;
    color: #111827;
    margin-bottom: 0;
}

.sub-title {
    font-size: 18px;
    color: #6B7280;
    margin-top: -5px;
    margin-bottom: 40px;
}

/ METRIC CARDS /
.metric-card {
    background: white;
    padding: 30px;
    border-radius: 22px;
    border: 1px solid #E5E7EB;
    box-shadow: 0 10px 30px rgba(0,0,0,0.06);
    transition: 0.3s ease;
    min-height: 160px;
}

.metric-card:hover {
    transform: translateY(-5px);
}

/ METRIC TITLE /
.metric-title {
    font-size: 20px;
    color: #6B7280;
    font-weight: 600;
}

/ METRIC VALUE /
.metric-value {
    font-size: 42px;
    font-weight: 800;
    margin-top: 15px;
    color: #111827;
}

/ METRIC SUB /
.metric-sub {
    font-size: 16px;
    color: #9CA3AF;
    margin-top: 10px;
}

/ ALERT BOX /
.alert-box {
    background: white;
    padding: 18px;
    border-radius: 16px;
    border-left: 5px solid #EF4444;
    margin-bottom: 14px;
    font-size: 18px;
    color: #111827;
    box-shadow: 0 4px 15px rgba(0,0,0,0.04);
}

/ SECTION TITLE /
.section-title {
    font-size: 30px;
    font-weight: 800;
    margin-top: 35px;
    margin-bottom: 20px;
    color: #111827;
}

/ FOOTER /
.footer {
    text-align: center;
    color: #6B7280;
    margin-top: 60px;
    font-size: 18px;
    padding-bottom: 30px;
}

/ CHART CONTAINERS /
.chart-box {
    background: white;
    padding: 25px;
    border-radius: 20px;
    border: 1px solid #E5E7EB;
    box-shadow: 0 8px 25px rgba(0,0,0,0.05);
}

/ NAV RADIO /
div[role="radiogroup"] label {
    padding: 12px !important;
    border-radius: 12px;
    margin-bottom: 8px;
    background: #F9FAFB;
}

/ DATAFRAME /
[data-testid="stDataFrame"] {
    border-radius: 18px;
    overflow: hidden;
}

/ BUTTONS /
.stButton button {
    background: #111827;
    color: white;
    border-radius: 12px;
    border: none;
    padding: 12px 22px;
    font-size: 16px;
    font-weight: 600;
}

.stDownloadButton button {
    background: #111827;
    color: white;
    border-radius: 12px;
    border: none;
    padding: 14px 22px;
    font-size: 16px;
}

/ MOBILE */
@media (max-width: 768px) {

    .main-title {
        font-size: 30px;
    }

    .metric-value {
        font-size: 32px;
    }

    .block-container {
        padding-left: 1rem;
        padding-right: 1rem;
    }
}

</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------
# SIDEBAR
# ---------------------------------------------------

with st.sidebar:

    st.image(
        "https://cdn-icons-png.flaticon.com/512/906/906324.png",
        width=90
    )

    st.markdown("## ThreatScope")

    st.caption("Enterprise Security Operations Center")

    st.divider()

    page = st.radio(
        "Navigation",
        [
            "Dashboard",
            "Analytics",
            "Threat Investigation",
            "Reports",
            "Assets"
        ]
    )

    st.divider()

    uploaded_file = st.file_uploader(
        "Upload Threat Dataset",
        type=["csv"]
    )

# ---------------------------------------------------
# HEADER
# ---------------------------------------------------

st.markdown(
    '<div class="main-title">ThreatScope</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="sub-title">Enterprise Cyber Threat Intelligence Platform</div>',
    unsafe_allow_html=True
)

# ---------------------------------------------------
# DASHBOARD
# ---------------------------------------------------

if page == "Dashboard":

    col1, col2, col3, col4 = st.columns(4)

    cards = [
        ("Threat Score", "89%", "+12% this hour"),
        ("Active Threats", "17", "Real-time monitoring"),
        ("Malware Alerts", "9", "Threat intelligence updated"),
        ("System Status", "Secure", "SOC operational")
    ]

    for col, card in zip([col1,col2,col3,col4], cards):

        with col:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-title">{card[0]}</div>
                <div class="metric-value">{card[1]}</div>
                <div class="metric-sub">{card[2]}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown(
        '<div class="section-title">🚨 Live Threat Feed</div>',
        unsafe_allow_html=True
    )

    alerts = [
        "DDoS Traffic Spike Detected",
        "Port Scanning Activity Identified",
        "Suspicious Login Attempt Blocked",
        "Malware Signature Match Found",
        "Privilege Escalation Attempt Detected"
    ]

    for alert in alerts:
        st.markdown(f"""
        <div class="alert-box">
            ⚠️ {alert}
        </div>
        """, unsafe_allow_html=True)

    st.markdown(
        '<div class="section-title">📊 Threat Analytics</div>',
        unsafe_allow_html=True
    )

    c1, c2 = st.columns(2)

    with c1:

        attack_data = pd.DataFrame({
            "Attack Type": ["DDoS","Malware","Botnet","Phishing","Brute Force"],
            "Count": [240,180,120,90,60]
        })

        fig1 = px.bar(
            attack_data,
            x="Attack Type",
            y="Count",
            color="Attack Type",
            template="plotly_white"
        )

        fig1.update_layout(
            height=500,
            paper_bgcolor="white",
            plot_bgcolor="white",
            font=dict(size=16)
        )

        st.plotly_chart(fig1, use_container_width=True)

    with c2:

        severity_data = pd.DataFrame({
            "Severity":["Critical","High","Medium","Low"],
            "Count":[45,35,15,5]
        })

        fig2 = px.pie(
            severity_data,
            names="Severity",
            values="Count",
            hole=0.5,
            template="plotly_white"
        )

        fig2.update_layout(
            height=500,
            font=dict(size=16)
        )

        st.plotly_chart(fig2, use_container_width=True)

# ---------------------------------------------------
# ANALYTICS PAGE
# ---------------------------------------------------

elif page == "Analytics":

    st.markdown(
        '<div class="section-title">📈 SOC Analytics Center</div>',
        unsafe_allow_html=True
    )

    traffic = pd.DataFrame({
        "Time":["10AM","11AM","12PM","1PM","2PM","3PM"],
        "Traffic":[120,180,300,260,340,420]
    })

    fig = px.line(
        traffic,
        x="Time",
        y="Traffic",
        markers=True,
        template="plotly_white"
    )

    fig.update_layout(
        height=600,
        font=dict(size=18)
    )

    st.plotly_chart(fig, use_container_width=True)

# ---------------------------------------------------
# THREAT INVESTIGATION
# ---------------------------------------------------

elif page == "Threat Investigation":

    st.markdown(
        '<div class="section-title">🕵️ Threat Investigation Console</div>',
        unsafe_allow_html=True
    )

    threat_data = pd.DataFrame({
        "IP Address": [
            "192.168.1.1",
            "10.0.0.5",
            "172.16.0.8"
        ],
        "Threat Type": [
            "DDoS",
            "Malware",
            "Botnet"
        ],
        "Severity": [
            "Critical",
            "High",
            "Medium"
        ]
    })

    st.dataframe(
        threat_data,
        use_container_width=True
    )

# ---------------------------------------------------
# REPORTS
# ---------------------------------------------------

elif page == "Reports":

    st.markdown(
        '<div class="section-title">📄 Threat Intelligence Reports</div>',
        unsafe_allow_html=True
    )

    report_data = pd.DataFrame({
        "Threat":["DDoS","Malware","Phishing"],
        "Severity":["Critical","High","Medium"]
    })

    st.dataframe(report_data, use_container_width=True)

    csv = report_data.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download Threat Report",
        data=csv,
        file_name="ThreatScope_Report.csv",
        mime="text/csv"
    )

# ---------------------------------------------------
# ASSETS
# ---------------------------------------------------

elif page == "Assets":

    st.markdown(
        '<div class="section-title">🖥️ Enterprise Assets</div>',
        unsafe_allow_html=True
    )

    assets = pd.DataFrame({
        "Device":["Firewall","SIEM","IDS","SOC Server"],
        "Status":["Active","Active","Monitoring","Secure"]
    })

    st.dataframe(assets, use_container_width=True)

# ---------------------------------------------------
# FOOTER
# ---------------------------------------------------

st.markdown("""
<div class="footer">
Engineered by Olawatosin Deborah Ajinomisan
</div>
""", unsafe_allow_html=True)
=======
# ThreatScope
>>>>>>> bda0c9ffdd8e6282b74f3ceb376ea15f26ef5c8c
