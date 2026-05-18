import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
from threat_lookup import classify_ip



# ---------------------------------------------
# PAGE CONFIG
# ---------------------------------------------



st.set_page_config(
    page_title="ThreatScope",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)



# ---------------------------------------------
# SESSION STATE
# ---------------------------------------------



if "alerts" not in st.session_state:



    st.session_state.alerts = 0
    st.session_state.critical = 0
    st.session_state.high = 0
    st.session_state.vulns = 0



    st.session_state.threat_data = {
        "Malware":0,
        "Phishing":0,
        "Intrusion":0,
        "DDoS":0,
        "Safe":1
    }



    st.session_state.feed = []
    st.session_state.incidents = []
    st.session_state.soc = []



def update_dashboard(threat, severity):



    st.session_state.alerts += 1



    if severity == "Critical":
        st.session_state.critical += 1



    if severity in ["Critical","High"]:
        st.session_state.high += 1



    st.session_state.vulns += 1



    if threat in st.session_state.threat_data:
        st.session_state.threat_data[threat] += 1



    time = datetime.now().strftime("%H:%M:%S")



    st.session_state.feed.insert(
        0,
        f"{time} - {threat} detected"
    )



    st.session_state.incidents.insert(
        0,
        f"{severity} {threat}"
    )



    st.session_state.soc.insert(
        0,
        f"{time} IOC analysed"
    )

# ---------------------------------------------
# CSS
# ---------------------------------------------

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

header{
visibility:hidden;
}

#MainMenu{
visibility:hidden;
}

.block-container{
padding-top:2rem;
padding-left:2rem;
padding-right:2rem;
}

.main-title{
font-size:58px;
font-weight:800;

background:
linear-gradient(
90deg,
white,
#4EA8FF
);

-webkit-background-clip:text;
-webkit-text-fill-color:transparent;
}

.sub-title{
font-size:22px;
color:#67B8FF;
margin-bottom:35px;
}

.metric-card{
background:#0B1325;
padding:25px;
border-radius:18px;
border:1px solid #16365D;

box-shadow:
0 0 20px rgba(0,150,255,.12);
}

.metric-value{
font-size:40px;
font-weight:800;
color:white;
}

.alert-box{
background:#081122;
padding:14px;
border-left:5px solid #FF3C5A;
margin-bottom:10px;
border-radius:12px;
}

.recent{
background:#081122;
padding:20px;
border-radius:18px;
border:1px solid #16365D;
}

.feed{
background:#081122;
padding:20px;
border-radius:18px;
border:1px solid #16365D;
}

.footer{
text-align:center;
color:#7DBFFF;
margin-top:40px;
}

/* SEARCH BAR */

.stTextInput > div > div > input{

background:#0B1325!important;

color:white!important;

border:1px solid #2B5C9A!important;

border-radius:12px!important;

padding:12px!important;

}

/* SEARCH PLACEHOLDER */

.stTextInput input::placeholder{

color:#9FC8FF!important;

opacity:1;

}

/* FILE UPLOADER */

[data-testid="stFileUploader"]{

background:#0B1325!important;

border:1px solid #2B5C9A!important;

border-radius:14px!important;

padding:10px!important;

}

/* UPLOAD TEXT */

[data-testid="stFileUploader"] *{

color:white!important;

}

/* ICON */

[data-testid="stFileUploader"] svg{

fill:#4EA8FF!important;

color:#4EA8FF!important;

}

/* INNER DROP ZONE */

[data-testid="stFileUploaderDropzone"]{

background:#0B1325!important;

border:1px dashed #4EA8FF!important;

border-radius:12px!important;

}

/* REMOVE WHITE BOX */

[data-testid="stFileUploaderDropzone"] *{

background:transparent!important;

color:white!important;

}

</style>
""", unsafe_allow_html=True)

# ---------------------------------------------
# HEADER
# ---------------------------------------------



st.markdown("""



<div class="main-title">



🛡 ThreatScope



</div>



<div class="sub-title">



Detect. Analyze. Protect.



</div>



""", unsafe_allow_html=True)


# ---------------------------------------------
# IOC INPUT + THREAT INVESTIGATION
# ---------------------------------------------

search_value = st.text_input(
    "Search IP / Domain / IOC"
)

uploaded_file = st.file_uploader(
    "Upload Threat Logs",
    type=["txt","csv","log"]
)


if uploaded_file:

    content = uploaded_file.read().decode(
        "utf-8"
    )

    lines = content.splitlines()

    st.markdown(
        "## 📂 Uploaded Log Analysis"
    )

    for line in lines:

        if "SRC=" in line:

            ip = line.split(
                "SRC="
            )[1].split()[0]

            result = classify_ip(ip)

            threat = result["threat"]

            severity = result["severity"]

            update_dashboard(
                threat,
                severity
            )

            st.info(f"""
IP: {ip}

Threat: {threat}

Severity: {severity}

Country: {result['country']}

Abuse Score: {result['abuse']}
""")

if search_value:

    result = classify_ip(
        search_value
    )

    threat = result["threat"]

    severity = result["severity"]

    update_dashboard(
        threat,
        severity
    )

    st.markdown(
        "## 🔎 Threat Investigation Result"
    )

    result_col1, result_col2 = st.columns(2)

    with result_col1:

        st.info(f"""
IOC: {search_value}

Threat Type: {threat}

Severity: {severity}

Country: {result["country"]}
""")

    with result_col2:

        st.warning(f"""
VirusTotal Detections: {result["vt"]}

Abuse Score: {result["abuse"]}

Status: {threat}
""")

    st.success(
        f"{threat} detected"
    )

# ---------------------------------------------
# DASHBOARD CARDS
# ---------------------------------------------



c1,c2,c3,c4 = st.columns(4)



cards=[



("Total Alerts",str(st.session_state.alerts)),
("Critical Threats",str(st.session_state.critical)),
("High Severity",str(st.session_state.high)),
("Vulnerabilities",str(st.session_state.vulns))



]



for col,card in zip(
[c1,c2,c3,c4],
cards
):



    with col:



        st.markdown(f"""



<div class="metric-card">



<h4>{card[0]}</h4>



<div class="metric-value">



{card[1]}



</div>



</div>



""", unsafe_allow_html=True)



# ---------------------------------------------
# ANALYTICS
# ---------------------------------------------



attacks = pd.DataFrame({



"Threat":
list(
st.session_state.threat_data.keys()
),



"Count":
list(
st.session_state.threat_data.values()
)



})



left,right=st.columns([2,1])



with left:



    fig = px.area(
        attacks,
        x="Threat",
        y="Count",
        template="plotly_dark"
    )



    fig.update_layout(
        paper_bgcolor="#081122",
        plot_bgcolor="#081122",
        font_color="white"
    )



    st.plotly_chart(
        fig,
        use_container_width=True
    )



with right:



    pie = px.pie(
        attacks,
        names="Threat",
        values="Count",
        hole=.55,
        template="plotly_dark"
    )



    pie.update_layout(
        paper_bgcolor="#081122",
        plot_bgcolor="#081122",
        font=dict(
            color="white"
        ),
        legend=dict(
            font=dict(
                color="white"
            )
        )
    )



    pie.update_traces(
        textfont=dict(
            color="white"
        )
    )



    st.plotly_chart(
        pie,
        use_container_width=True
    )



# ---------------------------------------------
# LIVE PANELS
# ---------------------------------------------



A,B,C=st.columns([2,1,1])



with A:



    st.markdown("## 🚨 Live Threat Feed")



    for alert in reversed(
        st.session_state.feed[-5:]
    ):



        st.markdown(
            f"""
<div class="alert-box">



{alert}



</div>
""",
unsafe_allow_html=True
)



with B:



    st.markdown(
        '<div class="recent"><h3>Recent Incidents</h3>',
        unsafe_allow_html=True
    )



    for i in st.session_state.incidents[-5:]:



        st.write(i)



    st.markdown(
        "</div>",
        unsafe_allow_html=True
    )



with C:



    st.markdown(
        '<div class="feed"><h3>SOC Activity</h3>',
        unsafe_allow_html=True
    )



    for item in st.session_state.soc[-5:]:



        st.write(item)



    st.markdown(
        "</div>",
        unsafe_allow_html=True
    )



# ---------------------------------------------
# FOOTER
# ---------------------------------------------



st.markdown("""



<div class="footer">



Engineered by Olawatosin Deborah Ajinomisan



</div>



""", unsafe_allow_html=True)

