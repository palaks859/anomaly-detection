"""
Renders a horizontal timeline of an incident's chained alerts using plotly,
ordered by chain_position, color-coded by risk score.
"""
import plotly.graph_objects as go


def render_timeline_plotly(incident_alerts_df):
    """
    incident_alerts_df: ordered rows (chain_position asc) for one incident.
    """
    if incident_alerts_df.empty:
        return go.Figure()

    df = incident_alerts_df.sort_values("chain_position")

    def risk_color(score):
        if score >= 70:
            return "#DE350B"  # red
        elif score >= 40:
            return "#FF8B00"  # orange
        return "#FFC400"      # yellow

    colors = [risk_color(s) for s in df["risk_score"]]
    hover_text = [
        f"Step {row['chain_position']}<br>"
        f"{row['timestamp']}<br>"
        f"Attack: {row['predicted_attack_type']}<br>"
        f"Resource: {row['resource']}<br>"
        f"Risk: {row['risk_score']:.1f}"
        for _, row in df.iterrows()
    ]

    fig = go.Figure()

    # connecting line
    fig.add_trace(go.Scatter(
        x=df["timestamp"], y=[1] * len(df),
        mode="lines",
        line=dict(color="gray", width=2, dash="dot"),
        hoverinfo="skip",
        showlegend=False
    ))

    # step markers
    fig.add_trace(go.Scatter(
        x=df["timestamp"], y=[1] * len(df),
        mode="markers+text",
        marker=dict(size=24, color=colors, line=dict(width=2, color="white")),
        text=[f"{i+1}" for i in range(len(df))],
        textposition="middle center",
        textfont=dict(color="white", size=11),
        hovertext=hover_text,
        hoverinfo="text",
        showlegend=False
    ))

    # attack-type labels below each step
    fig.add_trace(go.Scatter(
        x=df["timestamp"], y=[0.85] * len(df),
        mode="text",
        text=df["predicted_attack_type"],
        textposition="bottom center",
        textfont=dict(color="lightgray", size=10),
        hoverinfo="skip",
        showlegend=False
    ))

    fig.update_layout(
        height=220,
        margin=dict(l=10, r=10, t=10, b=10),
        yaxis=dict(visible=False, range=[0.5, 1.3]),
        xaxis=dict(title="Time", showgrid=False),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)"
    )
    return fig