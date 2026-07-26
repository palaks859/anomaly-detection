"""
Renders the top-3 deviating features for an alert as a horizontal bar chart,
using the |z-score| magnitude computed in the explainability layer (Step 9).
"""
import plotly.graph_objects as go

FEATURE_LABELS = {
    "failed_logins_5min": "Repeated failed logins",
    "geo_distance_km": "Login location far from usual",
    "device_known_baseline": "Device not previously seen",
    "resource_access_rate_10min": "Unusually high access rate",
    "hour_deviation": "Unusual login hour",
    "resource_outside_normal": "Resource outside normal role",
    "is_cold_start": "Limited history (cold start)"
}


def render_contribution_chart(reason_detail):
    """
    reason_detail: dict like {"failed_logins_5min": 4.2, "hour_deviation": 3.1, ...}
    """
    if not reason_detail:
        return go.Figure()

    items = sorted(reason_detail.items(), key=lambda x: abs(x[1]), reverse=True)
    labels = [FEATURE_LABELS.get(k, k) for k, _ in items]
    values = [abs(v) for _, v in items]
    colors = ["#DE350B" if v >= values[0] * 0.8 else "#FF8B00" for v in values]

    fig = go.Figure(go.Bar(
        x=values,
        y=labels,
        orientation="h",
        marker=dict(color=colors),
        text=[f"{v:.2f}σ" for v in values],
        textposition="outside"
    ))

    fig.update_layout(
        height=220,
        margin=dict(l=10, r=40, t=10, b=10),
        xaxis=dict(title="Deviation magnitude (|z-score|)", showgrid=False),
        yaxis=dict(autorange="reversed"),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)"
    )
    return fig