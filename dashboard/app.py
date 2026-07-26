"""
Streamlit dashboard: header, KPI row, filters, alert feed, detail panel.
"""
import streamlit as st
import pandas as pd
from datetime import datetime
from db_utils import load_alerts, load_evaluation_metrics

st.set_page_config(page_title="Behavioral Anomaly Detection", layout="wide")

# --- Header ---
col1, col2 = st.columns([4, 1])
with col1:
    st.title("🛡️ AI-Powered Behavioral Anomaly Detection")
with col2:
    st.markdown(
        f"<div style='text-align:right; padding-top:20px;'>"
        f"🟢 <b>Live</b><br><span style='font-size:12px'>Last refresh: "
        f"{datetime.now().strftime('%H:%M:%S')}</span></div>",
        unsafe_allow_html=True
    )

alerts_df = load_alerts()
metrics = load_evaluation_metrics()

if alerts_df.empty:
    st.warning("No alerts found. Run the pipeline steps (2 through 10) first.")
    st.stop()

alerts_today = alerts_df[
    alerts_df["timestamp"].dt.date == alerts_df["timestamp"].dt.date.max()
]
high_risk_count = (alerts_df["risk_score"] >= 70).sum()

# --- KPI Row ---
k1, k2, k3, k4 = st.columns(4)
k1.metric("Alerts (latest day)", len(alerts_today))
k2.metric("High-Risk Count", int(high_risk_count))
k3.metric("Model F1 Score", f"{metrics['f1_score']:.2f}" if metrics["f1_score"] else "N/A")
k4.metric("False Positive Rate", f"{metrics['fp_rate']*100:.1f}%" if metrics["fp_rate"] else "N/A")
st.divider()

sim_col1, sim_col2 = st.columns([1, 3])

with sim_col1:
    sim_attack_type = st.selectbox(
        "Attack type to simulate",
        [
            "random",
            "brute_force",
            "credential_misuse",
            "lateral_movement",
            "impossible_travel",
            "device_spoofing",
        ],
    )

with sim_col2:
    if st.button("⚡ Simulate Attack Live", use_container_width=True):
        import subprocess

        with st.spinner("Injecting attack and rescoring pipeline..."):
            chosen = None if sim_attack_type == "random" else sim_attack_type

            result = subprocess.run(
                ["python", "models/simulate_attack.py"],
                capture_output=True,
                text=True,
            )

        st.success("Simulation complete — refresh below to see the new alert.")
        st.code(result.stdout[-500:])
        st.cache_data.clear()
        st.rerun()

st.divider()

# --- Filters ---
f1, f2, f3 = st.columns([2, 2, 3])
with f1:
    attack_types = ["All"] + sorted(alerts_df["predicted_attack_type"].dropna().unique().tolist())
    selected_attack = st.selectbox("Attack Type", attack_types)
with f2:
    risk_levels = ["All", "High (>=70)", "Medium (40-69)", "Low (<40)"]
    selected_risk = st.selectbox("Risk Level", risk_levels)
with f3:
    search_query = st.text_input("Search by user/device", "")

filtered_df = alerts_df.copy()
if selected_attack != "All":
    filtered_df = filtered_df[filtered_df["predicted_attack_type"] == selected_attack]
if selected_risk == "High (>=70)":
    filtered_df = filtered_df[filtered_df["risk_score"] >= 70]
elif selected_risk == "Medium (40-69)":
    filtered_df = filtered_df[(filtered_df["risk_score"] >= 40) & (filtered_df["risk_score"] < 70)]
elif selected_risk == "Low (<40)":
    filtered_df = filtered_df[filtered_df["risk_score"] < 40]
if search_query:
    mask = (
        filtered_df["user_id"].str.contains(search_query, case=False, na=False) |
        filtered_df["device_id"].str.contains(search_query, case=False, na=False)
    )
    filtered_df = filtered_df[mask]

st.divider()

# --- Alert Feed + Detail Panel ---
left, right = st.columns([3, 2])

with left:
    st.subheader(f"Alert Feed ({len(filtered_df)} alerts)")

    def risk_color(score):
        if score >= 70:
            return "🔴"
        elif score >= 40:
            return "🟠"
        return "🟡"

    if "selected_alert_id" not in st.session_state:
        st.session_state.selected_alert_id = filtered_df.iloc[0]["alert_id"] if len(filtered_df) > 0 else None

    for _, row in filtered_df.head(50).iterrows():
        label = (
            f"{risk_color(row['risk_score'])} **{row['risk_score']:.0f}** | "
            f"{row['timestamp'].strftime('%Y-%m-%d %H:%M')} | "
            f"{row['user_id']} | {row['predicted_attack_type']}"
        )
        if st.button(label, key=f"alert_{row['alert_id']}", use_container_width=True):
            st.session_state.selected_alert_id = row["alert_id"]

with right:
    st.subheader("Detail Panel")
    if st.session_state.selected_alert_id:
        selected = alerts_df[alerts_df["alert_id"] == st.session_state.selected_alert_id].iloc[0]
        st.markdown(f"**User:** {selected['user_id']}")
        st.markdown(f"**Device:** {selected['device_id']}")
        st.markdown(f"**Resource:** {selected['resource']}")
        st.markdown(f"**Time:** {selected['timestamp']}")
        st.markdown(f"**Predicted Attack Type:** {selected['predicted_attack_type']}")
        st.markdown(f"**Risk Score:** {selected['risk_score']:.1f} / 100")
        st.markdown(f"**Isolation Forest Score:** {selected['iso_forest_score']:.3f}")
        st.markdown(f"**LOF Score:** {selected['lof_score']:.3f}")
        st.markdown(f"**Classifier Confidence:** {selected['classifier_confidence']:.3f}")
        st.divider()
        from db_utils import load_alert_reason_detail
        from contribution_utils import render_contribution_chart

        st.markdown("**Why this fired (top 3 reasons):**")
        reason_detail = load_alert_reason_detail(selected["alert_id"])
        if reason_detail:
            contrib_fig = render_contribution_chart(reason_detail)
            st.plotly_chart(contrib_fig, width="stretch")
        else:
            for reason in str(selected["top_reasons"]).split(";"):
                st.markdown(f"- {reason.strip()}")
        if pd.notna(selected["mitre_technique"]):
            st.divider()
            st.markdown(f"**MITRE ATT&CK:** {selected['mitre_technique']}")
            st.markdown(f"**Mitigation:** {selected['mitre_mitigation']}")
        if pd.notna(selected.get("llm_narrative")):
            st.divider()
            st.markdown("**🤖 Analyst Narrative:**")
            st.info(selected["llm_narrative"])
    else:
        st.info("Select an alert from the feed to see details.")
    st.divider()
    if st.button("🔍 Investigate Attack Path", use_container_width=True):
        st.session_state.investigating = True

if st.session_state.get("investigating") and st.session_state.selected_alert_id:
    from db_utils import load_incident_alerts, get_incident_id_for_alert
    from graph_utils import build_attack_graph, render_graph_plotly

    selected = alerts_df[
        alerts_df["alert_id"] == st.session_state.selected_alert_id
    ].iloc[0]

    incident_id = get_incident_id_for_alert(st.session_state.selected_alert_id)
    incident_alerts = load_incident_alerts(incident_id) if incident_id else pd.DataFrame()

    st.divider()
    st.header("🕵️ Attack Path Investigation")
    st.caption(f"Investigating incident for user {selected['user_id']} "
               f"({len(incident_alerts)} chained event(s))")

    if not incident_alerts.empty:
        G = build_attack_graph(incident_alerts)
        fig = render_graph_plotly(G)
        st.subheader("Access Graph (attack path in red)")
        st.plotly_chart(fig, width="stretch")
        from timeline_utils import render_timeline_plotly

        st.subheader("Incident Timeline")

        timeline_fig = render_timeline_plotly(incident_alerts)

        st.plotly_chart(timeline_fig, width="stretch")
    else:
        st.info("No incident chain data available for this alert.")