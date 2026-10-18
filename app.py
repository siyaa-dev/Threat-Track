"""
ThreatTrack - Vulnerability Triage and SLA Platform
Main Streamlit Dashboard Application
"""

import streamlit as st
import pandas as pd
import altair as alt
from datetime import datetime

# Local Utilities
from utils.data_loader import load_dataset
from utils.engine import (
    enrich_dataset,
    compute_metrics,
    get_top_high_risk_nodes,
    calculate_risk_score,
    evaluate_sla,
    ASSET_WEIGHTS,
    SLA_THRESHOLDS,
)
from utils.pdf_exporter import generate_executive_pdf

# Page Configuration
st.set_page_config(
    page_title="ThreatTrack | Vulnerability Triage & SLA Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom High-Tech Cyber SOC CSS
st.markdown(
    """
    <style>
    /* Dark Cyber Theme Adjustments */
    
    /* Top Banner Header */
    .top-header {
        background: linear-gradient(90deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
        padding: 1.2rem 1.8rem;
        border-radius: 10px;
        border: 1px solid #312e81;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .top-header h1 {
        margin: 0;
        font-size: 1.9rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        color: #ffffff;
    }
    .top-header p {
        margin: 0.3rem 0 0 0;
        color: #94a3b8;
        font-size: 0.95rem;
    }
    .status-badge {
        display: inline-block;
        padding: 0.25rem 0.65rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .status-active {
        background-color: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid #059669;
    }
    
    /* Metric Cards */
    .metric-card {
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 1.1rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .metric-card:hover {
        border-color: #64748b;
        transform: translateY(-2px);
    }
    .metric-title {
        font-size: 0.75rem;
        font-weight: 700;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 0.35rem;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 800;
        line-height: 1.1;
        margin-bottom: 0.25rem;
    }
    .metric-sub {
        font-size: 0.75rem;
        color: #64748b;
    }
    
    /* High Risk Alert Card */
    .metric-alert {
        border: 1px solid #ef4444;
    }
    
    /* Tables & Badges */
    .badge-breached {
        background-color: #7f1d1d;
        color: #fca5a5;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-atrisk {
        background-color: #78350f;
        color: #fde68a;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-insla {
        background-color: #064e3b;
        color: #a7f3d0;
        padding: 2px 8px;
        border-radius: 4px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data
def get_initial_data(seed: int = 42) -> pd.DataFrame:
    raw_df = load_dataset(count=100, seed=seed)
    return enrich_dataset(raw_df)


# Initialize Session State
if "seed" not in st.session_state:
    st.session_state.seed = 42

if "df" not in st.session_state:
    st.session_state.df = get_initial_data(st.session_state.seed)


# Sidebar Filters & Controls
with st.sidebar:
    st.markdown("### 🛡️ ThreatTrack Controls")
    st.markdown("Contextual Risk & SLA Platform")
    st.divider()

    st.markdown("#### 🔍 Filter Catalog")

    env_options = ["All", "Production", "Staging", "Internal"]
    selected_env = st.selectbox("Environment", env_options, index=0)

    severity_options = ["All", "Critical", "High", "Medium", "Low"]
    selected_severity = st.selectbox("Severity Tier", severity_options, index=0)

    sla_options = ["All", "BREACHED", "AT RISK", "IN SLA", "RESOLVED", "EXCEPTION"]
    selected_sla = st.selectbox("SLA Status", sla_options, index=0)

    search_query = st.text_input("Search (Asset, CVE, Component)", "").strip().lower()

    st.divider()
    st.markdown("#### ⚙️ Fleet Controls")
    if st.button("🔄 Reset / Re-seed Data", use_container_width=True):
        st.session_state.seed += 1
        st.session_state.df = get_initial_data(st.session_state.seed)
        st.rerun()

    st.caption("ThreatTrack v1.0 • Enterprise SecOps Edition")


# Apply Filters
filtered_df = st.session_state.df.copy()

if selected_env != "All":
    filtered_df = filtered_df[filtered_df["environment"] == selected_env]

if selected_severity != "All":
    filtered_df = filtered_df[filtered_df["severity"] == selected_severity]

if selected_sla != "All":
    filtered_df = filtered_df[filtered_df["sla_status"] == selected_sla]

if search_query:
    filtered_df = filtered_df[
        filtered_df["asset_id"].str.lower().str.contains(search_query)
        | filtered_df["asset_name"].str.lower().str.contains(search_query)
        | filtered_df["cve_id"].str.lower().str.contains(search_query)
        | filtered_df["affected_component"].str.lower().str.contains(search_query)
    ]

# Calculate Global and Filtered Metrics
global_metrics = compute_metrics(st.session_state.df)
view_metrics = compute_metrics(filtered_df)


# Top Banner Header
st.markdown(
    f"""
    <div class="top-header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1>🛡️ ThreatTrack</h1>
                <p>Enterprise Contextual Vulnerability Prioritization & SLA Governance Engine</p>
            </div>
            <div>
                <span class="status-badge status-active">● SLA ENGINE ACTIVE</span>
                <span style="color: #94a3b8; font-size: 0.8rem; margin-left: 0.75rem;">Seed #{st.session_state.seed}</span>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Executive KPI Ribbon (CISO Perspective)
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Fleet Backlog</div>
            <div class="metric-value" style="color: #38bdf8;">{view_metrics['active_backlog_count']}</div>
            <div class="metric-sub">{view_metrics['total_assets']} Assets Monitored</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Critical & High</div>
            <div class="metric-value" style="color: #f87171;">{view_metrics['critical_count'] + view_metrics['high_count']}</div>
            <div class="metric-sub">{view_metrics['critical_count']} Crit (9+) • {view_metrics['high_count']} High (7-8.9)</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col3:
    is_alert = view_metrics["breached_count"] > 0
    card_cls = "metric-card metric-alert" if is_alert else "metric-card"
    breached_color = "#ef4444" if is_alert else "#10b981"
    st.markdown(
        f"""
        <div class="{card_cls}">
            <div class="metric-title">SLA Breaches</div>
            <div class="metric-value" style="color: {breached_color};">{view_metrics['breached_count']}</div>
            <div class="metric-sub">{view_metrics['at_risk_count']} Items at Risk (&lt;25% SLA)</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col4:
    comp_color = "#34d399" if view_metrics["sla_compliance_pct"] >= 90.0 else "#fbbf24"
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">SLA Compliance</div>
            <div class="metric-value" style="color: {comp_color};">{view_metrics['sla_compliance_pct']}%</div>
            <div class="metric-sub">SLA Target: &ge; 95.0%</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col5:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">Mean Time to Remediate</div>
            <div class="metric-value" style="color: #a78bfa;">{view_metrics['mttr_days']}d</div>
            <div class="metric-sub">{view_metrics['resolved_count']} Resolved • Avg Open: {view_metrics['avg_days_open_backlog']}d</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.write("")

# Navigation Tabs
tab_triage, tab_analytics, tab_top5, tab_simulator, tab_export = st.tabs([
    "📋 SecOps Triage Console",
    "📊 Analytics & SLA Governance",
    "🎯 Top 5 High-Risk Nodes",
    "🧪 Contextual Risk Simulator",
    "📄 Executive PDF Export",
])


# ==========================================
# TAB 1: SECOPS TRIAGE CONSOLE
# ==========================================
with tab_triage:
    st.markdown("#### ⚡ Active Vulnerability Triage Queue")
    st.caption(
        "Showing "
        f"**{len(filtered_df)}** records matching current filters. "
        "Contextual Risk accounts for environment criticality (Production: 1.5x, Staging: 1.0x, Internal: 0.5x)."
    )

    display_cols = [
        "asset_id",
        "asset_name",
        "environment",
        "owner_team",
        "cve_id",
        "cvss_score",
        "risk_score",
        "days_open",
        "sla_target_days",
        "remaining_days",
        "sla_status",
        "status",
        "exploit_available",
    ]

    # Enhanced dataframe display
    st.dataframe(
        filtered_df[display_cols].sort_values(by=["risk_score", "days_open"], ascending=[False, False]),
        use_container_width=True,
        height=380,
        column_config={
            "risk_score": st.column_config.NumberColumn("Risk Score", format="%.2f", help="CVSS × Asset Weight"),
            "cvss_score": st.column_config.NumberColumn("CVSS v3", format="%.1f"),
            "days_open": st.column_config.NumberColumn("Days Open", format="%d d"),
            "remaining_days": st.column_config.NumberColumn("SLA Remaining", format="%d d"),
            "exploit_available": st.column_config.CheckboxColumn("Exploit In Wild"),
            "sla_status": st.column_config.TextColumn("SLA Status"),
        },
    )

    # Interactive Asset Inspector & Remediation Quick Actions
    st.markdown("---")
    st.markdown("#### 🔍 Asset Inspector & Remediation Action")

    if not filtered_df.empty:
        asset_list = filtered_df["asset_id"].tolist()
        inspect_id = st.selectbox("Select Asset to Inspect / Action:", asset_list, index=0)
        selected_record = filtered_df[filtered_df["asset_id"] == inspect_id].iloc[0]

        insp_col1, insp_col2, insp_col3 = st.columns([1.2, 1.2, 1.6])

        with insp_col1:
            st.markdown(f"**Asset:** `{selected_record['asset_name']}`")
            st.markdown(f"**ID:** `{selected_record['asset_id']}`")
            st.markdown(f"**Environment:** `{selected_record['environment']}` (Weight: x{selected_record['asset_weight']})")
            st.markdown(f"**IP Address:** `{selected_record['ip_address']}`")
            st.markdown(f"**Owner Team:** `{selected_record['owner_team']}`")

        with insp_col2:
            st.markdown(f"**Vulnerability:** `{selected_record['cve_id']}`")
            st.markdown(f"**Component:** `{selected_record['affected_component']}`")
            st.markdown(f"**CVSS Base Score:** `{selected_record['cvss_score']}` ({selected_record['severity']})")
            st.markdown(f"**Contextual Risk:** `{selected_record['risk_score']}` ({selected_record['risk_tier']})")
            st.markdown(f"**Exploit Available:** `{'YES' if selected_record['exploit_available'] else 'NO'}`")

        with insp_col3:
            st.markdown(f"**SLA Target Window:** `{selected_record['sla_target_days']} days`")
            st.markdown(f"**Aging:** `{selected_record['days_open']} days elapsed`")
            st.markdown(f"**SLA Health:** `{selected_record['sla_status']}`")

            # Quick Action Buttons
            st.markdown("**Update Status:**")
            btn_col1, btn_col2, btn_col3 = st.columns(3)
            with btn_col1:
                if st.button("Mark In-Progress", key=f"prog_{inspect_id}", use_container_width=True):
                    idx = st.session_state.df.index[st.session_state.df["asset_id"] == inspect_id].tolist()
                    if idx:
                        st.session_state.df.loc[idx[0], "status"] = "Remediation In Progress"
                        st.session_state.df = enrich_dataset(st.session_state.df)
                        st.rerun()

            with btn_col2:
                if st.button("Mark Resolved", key=f"res_{inspect_id}", use_container_width=True):
                    idx = st.session_state.df.index[st.session_state.df["asset_id"] == inspect_id].tolist()
                    if idx:
                        st.session_state.df.loc[idx[0], "status"] = "Resolved"
                        st.session_state.df = enrich_dataset(st.session_state.df)
                        st.rerun()

            with btn_col3:
                if st.button("Approve Exception", key=f"exc_{inspect_id}", use_container_width=True):
                    idx = st.session_state.df.index[st.session_state.df["asset_id"] == inspect_id].tolist()
                    if idx:
                        st.session_state.df.loc[idx[0], "status"] = "Exception Approved"
                        st.session_state.df = enrich_dataset(st.session_state.df)
                        st.rerun()
    else:
        st.info("No vulnerabilities match the current filter selection.")


# ==========================================
# TAB 2: ANALYTICS & SLA GOVERNANCE
# ==========================================
with tab_analytics:
    st.markdown("#### 📊 Fleet Risk & SLA Compliance Analytics")

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("**Risk Score Distribution by Environment**")
        env_summary = (
            st.session_state.df.groupby("environment")
            .agg(
                mean_risk=("risk_score", "mean"),
                mean_cvss=("cvss_score", "mean"),
                vuln_count=("cve_id", "count"),
                breached_count=("is_breached", "sum"),
            )
            .reset_index()
        )

        chart1 = (
            alt.Chart(env_summary)
            .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
            .encode(
                x=alt.X("environment:N", title="Environment", sort=["Production", "Staging", "Internal"]),
                y=alt.Y("mean_risk:Q", title="Mean Contextual Risk Score"),
                color=alt.Color(
                    "environment:N",
                    scale=alt.Scale(
                        domain=["Production", "Staging", "Internal"],
                        range=["#ef4444", "#38bdf8", "#10b981"],
                    ),
                    legend=None,
                ),
                tooltip=["environment", "mean_risk", "mean_cvss", "vuln_count", "breached_count"],
            )
            .properties(height=260)
        )
        st.altair_chart(chart1, use_container_width=True)

    with chart_col2:
        st.markdown("**SLA Status Breakdown (Active Fleet)**")
        sla_counts = (
            st.session_state.df[st.session_state.df["status"] != "Resolved"]["sla_status"]
            .value_counts()
            .reset_index()
        )
        sla_counts.columns = ["sla_status", "count"]

        chart2 = (
            alt.Chart(sla_counts)
            .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
            .encode(
                x=alt.X("sla_status:N", title="SLA Status", sort=["BREACHED", "AT RISK", "IN SLA", "EXCEPTION"]),
                y=alt.Y("count:Q", title="Vulnerabilities Count"),
                color=alt.Color(
                    "sla_status:N",
                    scale=alt.Scale(
                        domain=["BREACHED", "AT RISK", "IN SLA", "EXCEPTION"],
                        range=["#ef4444", "#f59e0b", "#10b981", "#6366f1"],
                    ),
                    legend=None,
                ),
                tooltip=["sla_status", "count"],
            )
            .properties(height=260)
        )
        st.altair_chart(chart2, use_container_width=True)

    st.markdown("---")
    st.markdown("**Vulnerability Aging vs. SLA Thresholds (Days Open)**")

    aging_chart = (
        alt.Chart(st.session_state.df)
        .mark_circle(size=70, opacity=0.75)
        .encode(
            x=alt.X("days_open:Q", title="Days Elapsed Since Discovery"),
            y=alt.Y("risk_score:Q", title="Contextual Risk Score (CVSS × Weight)"),
            color=alt.Color(
                "sla_status:N",
                scale=alt.Scale(
                    domain=["BREACHED", "AT RISK", "IN SLA", "RESOLVED", "EXCEPTION"],
                    range=["#ef4444", "#f59e0b", "#10b981", "#64748b", "#818cf8"],
                ),
                title="SLA Status",
            ),
            tooltip=["asset_id", "asset_name", "environment", "cve_id", "cvss_score", "risk_score", "days_open", "sla_status"],
        )
        .properties(height=280)
    )
    st.altair_chart(aging_chart, use_container_width=True)


# ==========================================
# TAB 3: TOP 5 HIGH-RISK NODES
# ==========================================
with tab_top5:
    st.markdown("#### 🎯 Top 5 Prioritized High-Risk Nodes")
    st.caption("Fleet nodes carrying the highest contextual risk score, accounting for base vulnerability severity and asset environment.")

    top5_df = get_top_high_risk_nodes(st.session_state.df, top_n=5)

    for rank, (_, row) in enumerate(top5_df.iterrows(), start=1):
        breached = row["sla_status"] == "BREACHED"
        border_color = "#ef4444" if breached else "#f59e0b"

        with st.container():
            st.markdown(
                f"""
                <div style="background-color: #1e293b; border-left: 5px solid {border_color}; border-radius: 6px; padding: 1rem; margin-bottom: 0.85rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-weight: 800; font-size: 1.1rem; color: #ffffff;">#{rank} • {row['asset_name']} <span style="font-size: 0.85rem; color: #94a3b8;">({row['asset_id']})</span></span>
                        <span style="font-size: 1.1rem; font-weight: 800; color: #ef4444;">Contextual Risk: {row['risk_score']}</span>
                    </div>
                    <div style="margin-top: 0.5rem; display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; font-size: 0.85rem; color: #cbd5e1;">
                        <div><strong>Env:</strong> {row['environment']} (1.5x)</div>
                        <div><strong>Vulnerability:</strong> {row['cve_id']} (CVSS {row['cvss_score']})</div>
                        <div><strong>Days Open:</strong> {row['days_open']}d (Target: {row['sla_target_days']}d)</div>
                        <div><strong>Status:</strong> <span style="color: {border_color}; font-weight: 700;">{row['sla_status']}</span></div>
                    </div>
                    <div style="margin-top: 0.4rem; font-size: 0.8rem; color: #94a3b8;">
                        <em>Action Directive:</em> Apply emergency patch for <strong>{row['affected_component']}</strong>. Exploit active: <strong>{'YES' if row['exploit_available'] else 'NO'}</strong>. Owner: <strong>{row['owner_team']}</strong>.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


# ==========================================
# TAB 4: CONTEXTUAL RISK SIMULATOR
# ==========================================
with tab_simulator:
    st.markdown("#### 🧪 Contextual Risk Simulator & What-If Analyzer")
    st.caption("Simulate how changing asset environments and vulnerability severities alters operational priority and SLA windows.")

    sim_col1, sim_col2 = st.columns([1, 1.2])

    with sim_col1:
        st.markdown("**Scenario Inputs**")
        sim_cvss = st.slider("CVSS v3.1 Base Score", min_value=1.0, max_value=10.0, value=9.8, step=0.1)
        sim_env = st.selectbox("Asset Criticality Environment", ["Production", "Staging", "Internal"], index=0)
        sim_days_open = st.number_input("Days Elapsed Since Discovery", min_value=0, max_value=120, value=12, step=1)
        sim_status = st.selectbox("Current Lifecycle State", ["Open", "In Triage", "Remediation In Progress", "Resolved"], index=0)

    # Compute live simulation
    sim_weight = ASSET_WEIGHTS[sim_env]
    sim_risk = calculate_risk_score(sim_cvss, sim_env)
    sim_sla = evaluate_sla(sim_cvss, sim_days_open, sim_status)

    with sim_col2:
        st.markdown("**Simulation Evaluation**")

        st.markdown(
            f"""
            <div style="background-color: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.2rem;">
                <div style="font-size: 0.85rem; color: #94a3b8; font-weight: 600;">CALCULATED CONTEXTUAL RISK SCORE</div>
                <div style="font-size: 2.2rem; font-weight: 800; color: #ef4444; margin: 0.2rem 0;">{sim_risk}</div>
                <div style="font-size: 0.85rem; color: #cbd5e1; margin-bottom: 0.8rem;">
                    Formula: CVSS ({sim_cvss}) &times; Weight ({sim_weight} for {sim_env})
                </div>
                <div style="border-top: 1px solid #334155; padding-top: 0.8rem; display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.85rem; color: #94a3b8;">
                    <div><strong>Severity Tier:</strong> {sim_sla['severity']}</div>
                    <div><strong>SLA Window:</strong> {sim_sla['sla_target_days']} Calendar Days</div>
                    <div><strong>Remaining Days:</strong> {sim_sla['remaining_days']} Days</div>
                    <div><strong>Compliance State:</strong> <span style="font-weight: 800; color: {'#ef4444' if sim_sla['is_breached'] else '#10b981'};">{sim_sla['sla_status']}</span></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.write("")
        if sim_env == "Production" and sim_cvss >= 9.0:
            st.error("🚨 CRITICAL PRODUCTION MANDATE: Requires immediate escalation to Platform On-Call and CISO notification.")
        elif sim_sla["is_breached"]:
            st.warning("⚠️ SLA VIOLATION: Vulnerability has exceeded policy remediation timeline.")
        else:
            st.success("✅ COMPLIANT: Vulnerability is currently within defined SLA remediation parameters.")


# ==========================================
# TAB 5: EXECUTIVE PDF EXPORTER
# ==========================================
with tab_export:
    st.markdown("#### 📄 Executive Triage Report & Compliance Audit Brief")
    st.caption("Generate an audit-ready, 1-page executive PDF briefing for CISOs and Risk Governance committees.")

    exp_col1, exp_col2 = st.columns([1.2, 1])

    with exp_col1:
        st.markdown("**Executive Brief Summary:**")
        st.markdown(
            f"""
            - **Fleet Scope:** {global_metrics['total_assets']} monitored assets with {global_metrics['total_vulnerabilities']} total CVE records.
            - **Current SLA Compliance:** `{global_metrics['sla_compliance_pct']}%` ({global_metrics['breached_count']} active breaches).
            - **Fleet MTTR:** `{global_metrics['mttr_days']} days` across resolved remediation cycles.
            - **Top High-Risk Nodes:** 5 production/staging assets flagged for immediate containment.
            """
        )

    with exp_col2:
        st.markdown("**Generate Certified PDF:**")

        # Compile PDF button
        top_5_nodes = get_top_high_risk_nodes(st.session_state.df, top_n=5)
        env_breakdown = (
            st.session_state.df.groupby("environment")
            .agg(
                asset_weight=("asset_weight", "first"),
                total_vulns=("cve_id", "count"),
                breached_vulns=("is_breached", "sum"),
                mean_risk=("risk_score", "mean"),
            )
            .reset_index()
        )

        try:
            pdf_bytes = generate_executive_pdf(global_metrics, top_5_nodes, env_breakdown)
            report_name = f"ThreatTrack_Executive_Brief_{datetime.now().strftime('%Y%m%d')}.pdf"

            st.download_button(
                label="📥 Download Executive PDF Report",
                data=pdf_bytes,
                file_name=report_name,
                mime="application/pdf",
                use_container_width=True,
            )
            st.success("PDF ready for download!")
        except Exception as e:
            st.error(f"Error compiling PDF report: {e}")
