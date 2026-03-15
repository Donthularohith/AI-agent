"""
SOC Dashboard — Streamlit Application

4-tab dashboard for security operations:
  Tab 1: Agent Fleet — status overview of all registered agents
  Tab 2: Live Anomalies — real-time anomaly event feed
  Tab 3: Audit Timeline — per-agent action history
  Tab 4: Blast Radius — compromised agent impact assessment

Rohith: This is your SOC single-pane-of-glass for AI agents — same
workflow as CrowdStrike Falcon dashboard or Splunk ES Security Posture.
"""

import os
import time
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime, timedelta

# ── Configuration ───────────────────────────────────────────────────────────
API_URL = os.getenv("API_URL", "http://localhost:8000")

st.set_page_config(
    page_title="AI Agent Governance — SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom Styling ──────────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #0e1117; }
    .metric-card {
        background: linear-gradient(135deg, #1a1f2e 0%, #252b3b 100%);
        border: 1px solid #2d3748;
        border-radius: 12px;
        padding: 20px;
        margin: 8px 0;
    }
    .status-active { color: #48bb78; font-weight: bold; }
    .status-suspended { color: #ed8936; font-weight: bold; }
    .status-revoked { color: #fc8181; font-weight: bold; }
    .severity-critical { background-color: #fc8181; color: #1a1f2e; padding: 2px 8px; border-radius: 4px; }
    .severity-high { background-color: #ed8936; color: #1a1f2e; padding: 2px 8px; border-radius: 4px; }
    .severity-medium { background-color: #ecc94b; color: #1a1f2e; padding: 2px 8px; border-radius: 4px; }
    .severity-low { background-color: #48bb78; color: #1a1f2e; padding: 2px 8px; border-radius: 4px; }
    h1 { color: #e2e8f0; }
    h2 { color: #a0aec0; }
    h3 { color: #cbd5e0; }
</style>
""", unsafe_allow_html=True)


# ── Helper Functions ────────────────────────────────────────────────────────
def api_get(endpoint: str, params: dict = None) -> dict:
    """Make GET request to governance API."""
    try:
        resp = requests.get(f"{API_URL}{endpoint}", params=params, timeout=5)
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"API returned {resp.status_code}"}
    except requests.ConnectionError:
        return {"error": "Cannot connect to governance API"}
    except Exception as e:
        return {"error": str(e)}


def api_post(endpoint: str, json_data: dict = None) -> dict:
    """Make POST request to governance API."""
    try:
        resp = requests.post(f"{API_URL}{endpoint}", json=json_data, timeout=5)
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def status_badge(status: str) -> str:
    """Create HTML badge for agent status."""
    colors = {
        "active": "#48bb78",
        "suspended": "#ed8936",
        "revoked": "#fc8181",
        "expired": "#a0aec0",
    }
    color = colors.get(status, "#a0aec0")
    return f'<span style="background:{color};color:#1a1f2e;padding:2px 10px;border-radius:12px;font-weight:bold;font-size:12px;">{status.upper()}</span>'


# ── Sidebar ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("🛡️ AI Governance")
    st.markdown("---")
    st.markdown("**Platform Status**")

    # Health check
    health = api_get("/health")
    if "error" not in health:
        st.success(f"API: {health.get('status', 'unknown')}")
        st.info(f"DB: {health.get('database', 'unknown')}")
        st.info(f"OPA: {health.get('opa', 'unknown')}")
        st.info(f"Vault: {health.get('vault', 'unknown')}")
    else:
        st.error(f"API: {health.get('error', 'unreachable')}")

    st.markdown("---")
    auto_refresh = st.checkbox("Auto-refresh (10s)", value=False)
    if auto_refresh:
        time.sleep(10)
        st.rerun()


# ── Main Content ────────────────────────────────────────────────────────────
st.title("🛡️ AI Agent Identity Governance Platform")
st.caption("SOC Dashboard — Real-time monitoring of AI agent fleet")

tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Agent Fleet",
    "🚨 Live Anomalies",
    "📜 Audit Timeline",
    "💥 Blast Radius",
])


# ═══════════════════════════════════════════════════════════════
# TAB 1: Agent Fleet
# ═══════════════════════════════════════════════════════════════
with tab1:
    st.header("Agent Fleet Overview")

    agents_data = api_get("/agents", params={"page_size": 100})

    if "error" in agents_data:
        st.error(f"Failed to load agents: {agents_data['error']}")
    else:
        agents = agents_data.get("agents", [])
        total = agents_data.get("total", 0)

        # Metrics row
        col1, col2, col3, col4 = st.columns(4)
        active = sum(1 for a in agents if a.get("status") == "active")
        suspended = sum(1 for a in agents if a.get("status") == "suspended")
        revoked_count = sum(1 for a in agents if a.get("status") == "revoked")
        hipaa = sum(1 for a in agents if "HIPAA" in a.get("compliance_tags", []))

        col1.metric("Total Agents", total)
        col2.metric("Active", active, delta=None)
        col3.metric("Suspended", suspended, delta=None)
        col4.metric("HIPAA Tagged", hipaa)

        # Agent table
        if agents:
            df = pd.DataFrame(agents)
            display_cols = ["name", "status", "owner_email", "version", "expires_at", "compliance_tags"]
            available_cols = [c for c in display_cols if c in df.columns]
            if available_cols:
                st.dataframe(
                    df[available_cols],
                    use_container_width=True,
                    hide_index=True,
                )

            # Status distribution chart
            if "status" in df.columns:
                fig = px.pie(
                    df, names="status", title="Agent Status Distribution",
                    color="status",
                    color_discrete_map={
                        "active": "#48bb78", "suspended": "#ed8936",
                        "revoked": "#fc8181", "expired": "#a0aec0",
                    },
                )
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#e2e8f0",
                )
                st.plotly_chart(fig, use_container_width=True)

            # Quick actions
            st.subheader("Quick Actions")
            col_a, col_b = st.columns(2)
            with col_a:
                agent_to_suspend = st.selectbox(
                    "Select agent to suspend",
                    options=[a["name"] for a in agents if a.get("status") == "active"],
                    key="suspend_select",
                )
                if st.button("⚠️ Suspend Agent", key="suspend_btn"):
                    target = next((a for a in agents if a["name"] == agent_to_suspend), None)
                    if target:
                        result = api_post(f"/agents/{target['agent_id']}/suspend")
                        if "error" not in result:
                            st.success(f"Agent {agent_to_suspend} suspended")
                            st.rerun()
                        else:
                            st.error(f"Failed: {result}")
        else:
            st.info("No agents registered yet. Use POST /agents to register.")


# ═══════════════════════════════════════════════════════════════
# TAB 2: Live Anomalies
# ═══════════════════════════════════════════════════════════════
with tab2:
    st.header("🚨 Live Anomaly Feed")

    anomalies_data = api_get("/audit/anomalies", params={"limit": 50})

    if "error" in anomalies_data:
        st.warning(f"Anomaly feed unavailable: {anomalies_data.get('error')}")
        st.info("Anomalies will appear here once agents are monitored and baseline models are trained.")
    else:
        events = anomalies_data.get("events", [])

        if events:
            st.metric("Open Anomalies", len([e for e in events if not e.get("resolved")]))

            for event in events:
                severity = "CRITICAL" if event["anomaly_score"] < -0.7 else "HIGH" if event["anomaly_score"] < -0.5 else "MEDIUM"
                with st.expander(
                    f"🔴 {event.get('agent_id', 'unknown')[:8]}... | "
                    f"Score: {event['anomaly_score']:.3f} | "
                    f"{severity} | "
                    f"{event.get('timestamp_utc', 'unknown')}"
                ):
                    col1, col2 = st.columns(2)
                    col1.metric("Anomaly Score", f"{event['anomaly_score']:.3f}")
                    col2.metric("Threshold", f"{event.get('threshold', -0.3):.3f}")

                    st.json(event.get("feature_vector", {}))

                    if not event.get("resolved"):
                        if st.button(f"✅ Resolve", key=f"resolve_{event['id']}"):
                            st.info("Resolution requires notes — use the API endpoint")
        else:
            st.success("✅ No anomalies detected — all agents operating normally")
            st.info(
                "Anomaly detection requires:\n"
                "1. At least 100 agent actions to build baseline\n"
                "2. An action that deviates from learned patterns"
            )


# ═══════════════════════════════════════════════════════════════
# TAB 3: Audit Timeline
# ═══════════════════════════════════════════════════════════════
with tab3:
    st.header("📜 Audit Timeline")

    # Agent selector
    agents_data = api_get("/agents", params={"page_size": 100})
    agents_list = agents_data.get("agents", []) if "error" not in agents_data else []

    if agents_list:
        selected_agent_name = st.selectbox(
            "Select Agent",
            options=[a["name"] for a in agents_list],
            key="audit_agent_select",
        )
        selected_agent = next(
            (a for a in agents_list if a["name"] == selected_agent_name), None
        )

        if selected_agent:
            # Filters
            col1, col2 = st.columns(2)
            with col1:
                tool_filter = st.text_input("Filter by tool_uri", key="tool_filter")
            with col2:
                outcome_filter = st.selectbox(
                    "Filter by outcome",
                    options=["All", "success", "denied", "error"],
                    key="outcome_filter",
                )

            params = {"page_size": 100}
            if tool_filter:
                params["tool"] = tool_filter
            if outcome_filter != "All":
                params["outcome"] = outcome_filter

            audit_data = api_get(
                f"/audit/agents/{selected_agent['agent_id']}", params=params
            )

            if "error" not in audit_data:
                entries = audit_data.get("entries", [])
                if entries:
                    df = pd.DataFrame(entries)
                    display_cols = [
                        "timestamp_utc", "action_type", "tool_uri",
                        "resource", "outcome", "anomaly_score",
                    ]
                    available_cols = [c for c in display_cols if c in df.columns]
                    st.dataframe(df[available_cols], use_container_width=True, hide_index=True)

                    # Outcome distribution
                    if "outcome" in df.columns:
                        fig = px.histogram(
                            df, x="outcome", title="Action Outcomes",
                            color="outcome",
                            color_discrete_map={
                                "success": "#48bb78", "denied": "#fc8181", "error": "#ed8936"
                            },
                        )
                        fig.update_layout(
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="rgba(0,0,0,0)",
                            font_color="#e2e8f0",
                        )
                        st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No audit entries for this agent yet.")
            else:
                st.error(f"Failed to load audit: {audit_data.get('error')}")
    else:
        st.info("No agents registered. Register agents via POST /agents first.")


# ═══════════════════════════════════════════════════════════════
# TAB 4: Blast Radius
# ═══════════════════════════════════════════════════════════════
with tab4:
    st.header("💥 Blast Radius Estimator")
    st.caption(
        "Select a potentially compromised agent to assess the impact scope. "
        "This shows what resources, tools, and child agents would be affected."
    )

    agents_data = api_get("/agents", params={"page_size": 100})
    agents_list = agents_data.get("agents", []) if "error" not in agents_data else []

    if agents_list:
        selected_name = st.selectbox(
            "Select compromised agent for analysis",
            options=[a["name"] for a in agents_list],
            key="blast_agent_select",
        )
        selected = next((a for a in agents_list if a["name"] == selected_name), None)

        if selected and st.button("🔍 Analyze Blast Radius"):
            st.subheader(f"Impact Analysis: {selected['name']}")

            # Agent details
            col1, col2, col3 = st.columns(3)
            col1.metric("Status", selected.get("status", "unknown").upper())
            col2.metric("Owner", selected.get("owner_email", "unknown"))
            col3.metric("Compliance", ", ".join(selected.get("compliance_tags", [])) or "None")

            # Accessible resources
            st.subheader("📂 Accessible Resources")
            resources = selected.get("allowed_resources", [])
            for r in resources:
                is_hipaa = "patient" in r.lower() or "emr" in r.lower()
                icon = "🏥" if is_hipaa else "📁"
                tag = " **[HIPAA/PHI]**" if is_hipaa else ""
                st.markdown(f"  {icon} `{r}`{tag}")

            # Accessible tools
            st.subheader("🔧 Accessible Tools")
            tools = selected.get("allowed_tools", [])
            for t in tools:
                is_write = "write" in t.lower() or "admin" in t.lower()
                icon = "⚠️" if is_write else "🔧"
                tag = " **[WRITE ACCESS]**" if is_write else ""
                st.markdown(f"  {icon} `{t}`{tag}")

            # Risk assessment
            st.subheader("⚡ Risk Assessment")
            risk_score = len(resources) * 2 + len(tools) * 3
            hipaa_count = sum(1 for r in resources if "patient" in r.lower() or "emr" in r.lower())

            if risk_score >= 30 or hipaa_count > 0:
                st.error(f"🔴 **CRITICAL RISK** — {hipaa_count} HIPAA resources exposed")
                st.warning(
                    "**Recommended Actions:**\n"
                    "1. Immediately suspend the agent\n"
                    "2. Revoke all credentials\n"
                    "3. Check audit log for unauthorized data access\n"
                    "4. Notify HIPAA Privacy Officer if PHI exposure suspected"
                )
            elif risk_score >= 15:
                st.warning("🟡 **HIGH RISK**")
            else:
                st.info("🟢 **LOW RISK**")

            # Delegation chain
            st.subheader("🔗 Delegation Chain")
            max_depth = selected.get("max_delegation_depth", 0)
            parent = selected.get("parent_agent_id")
            st.markdown(f"- Max delegation depth: **{max_depth}**")
            st.markdown(f"- Parent agent: **{parent or 'None (root agent)'}**")
            if max_depth > 0:
                st.warning(
                    f"This agent can spawn up to {max_depth} levels of child agents. "
                    f"If compromised, all child agents should be suspended."
                )
    else:
        st.info("No agents registered. Register agents to use blast radius analysis.")

# Footer
st.markdown("---")
st.caption(
    f"AI Agent Identity Governance Platform v1.0.0 | "
    f"Last refresh: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
    f"Built by Rohith Donthula"
)
