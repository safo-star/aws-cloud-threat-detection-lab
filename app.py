import streamlit as st
from detector import load_logs, analyze_cloud_logs, summarize_alerts

st.set_page_config(
    page_title="AWS Cloud Threat Detection Lab",
    page_icon="☁️",
    layout="wide"
)

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(135deg, #05070d 0%, #0b1120 50%, #111827 100%);
        color: #f8fafc;
    }

    h1, h2, h3 {
        font-family: 'Inter', 'Segoe UI', sans-serif;
        letter-spacing: -0.03em;
    }

    h1 {
        font-size: 3rem !important;
        font-weight: 850 !important;
        color: #ffffff;
    }

    p, label, span, div {
        font-family: 'Inter', 'Segoe UI', sans-serif;
    }

    .hero-card {
        padding: 2rem;
        border-radius: 18px;
        background: rgba(15, 23, 42, 0.85);
        border: 1px solid rgba(148, 163, 184, 0.25);
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.35);
        margin-bottom: 2rem;
    }

    .brand-badge {
        display: inline-block;
        padding: 0.45rem 0.85rem;
        border-radius: 999px;
        background: rgba(37, 99, 235, 0.15);
        border: 1px solid rgba(59, 130, 246, 0.45);
        color: #93c5fd;
        font-weight: 700;
        font-size: 0.85rem;
        margin-bottom: 1rem;
    }

    .hero-subtitle {
        font-size: 1.05rem;
        color: #cbd5e1;
        line-height: 1.7;
        max-width: 1050px;
    }

    .small-muted {
        color: #94a3b8;
        font-size: 0.9rem;
    }

    .alert-card {
        padding: 1.2rem;
        border-radius: 16px;
        background: rgba(15, 23, 42, 0.75);
        border: 1px solid rgba(148, 163, 184, 0.22);
        margin-bottom: 1rem;
    }

    div[data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.75);
        border: 1px solid rgba(148, 163, 184, 0.22);
        padding: 1rem;
        border-radius: 16px;
    }

    .stButton > button {
        border-radius: 12px;
        padding: 0.65rem 1.2rem;
        font-weight: 700;
        border: 1px solid rgba(59, 130, 246, 0.8);
        background: linear-gradient(135deg, #2563eb, #1d4ed8);
        color: white;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.markdown(
    """
    <div class="hero-card">
        <div class="brand-badge">SAFO SECURITY • CLOUD SECURITY LAB</div>
        <h1>AWS Cloud Threat Detection Lab</h1>
        <p class="hero-subtitle">
            A cloud security monitoring lab that analyzes simulated AWS CloudTrail-style logs and detects suspicious activity
            such as failed login bursts, root account usage, MFA being disabled, administrator permissions being added,
            S3 bucket exposure, large data downloads, access key creation, and CloudTrail logging being stopped.
        </p>
        <p class="small-muted">
            Built to demonstrate SOC analyst thinking, cloud IAM awareness, detection engineering, and business-risk explanation.
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

st.subheader("Cloud Threat Detection Dashboard")

logs = load_logs()
alerts = analyze_cloud_logs(logs)
summary = summarize_alerts(alerts)

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Alerts", summary["total_alerts"])

with col2:
    st.metric("Critical", summary["critical"])

with col3:
    st.metric("High", summary["high"])

with col4:
    st.metric("Medium", summary["medium"])

st.divider()

st.subheader("Detection Categories")

cat1, cat2, cat3 = st.columns(3)

with cat1:
    st.markdown(
        """
        <div class="alert-card">
            <h4>Identity Threats</h4>
            <p>Detects root account usage, MFA disabled, administrator policy changes, and access key creation.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

with cat2:
    st.markdown(
        """
        <div class="alert-card">
            <h4>S3 Data Risk</h4>
            <p>Detects public bucket exposure and unusually large S3 downloads that may indicate data exfiltration.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

with cat3:
    st.markdown(
        """
        <div class="alert-card">
            <h4>Visibility Loss</h4>
            <p>Detects CloudTrail logging being stopped, which can reduce investigation visibility after compromise.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

st.divider()

st.subheader("Detected Alerts")

for alert in alerts:
    severity = alert["severity"]

    if severity == "Critical":
        st.error(f"🚨 {alert['alert_name']} — {severity} — Risk Score: {alert['risk_score']}/100")
    elif severity == "High":
        st.warning(f"⚠️ {alert['alert_name']} — {severity} — Risk Score: {alert['risk_score']}/100")
    else:
        st.info(f"ℹ️ {alert['alert_name']} — {severity} — Risk Score: {alert['risk_score']}/100")

    with st.container(border=True):
        st.write(f"**Timestamp:** {alert['timestamp']}")
        st.write(f"**User:** {alert['user']}")
        st.write(f"**Source IP:** {alert['source_ip']}")
        st.write(f"**Event Source:** {alert['event_source']}")
        st.write(f"**Description:** {alert['description']}")
        st.write(f"**Recommendation:** {alert['recommendation']}")

st.divider()

st.subheader("Raw Log Sample")

with st.expander("View Simulated AWS CloudTrail Logs"):
    st.json(logs)

st.subheader("Technical JSON Alert Output")

with st.expander("View Alert JSON"):
    st.json(alerts)

st.markdown(
    """
    <div class="hero-card">
        <h3>Business Value</h3>
        <p class="hero-subtitle">
            This lab shows how cloud security monitoring can reduce business risk by detecting suspicious cloud activity early.
            In a real company, these detections could help security teams respond to account compromise, privilege abuse,
            public data exposure, logging tampering, and possible cloud data exfiltration before major damage occurs.
        </p>
    </div>
    """,
    unsafe_allow_html=True
)