"""
Builds an access graph (user -> device -> resource) and highlights the
attack path for a given incident's alert chain, using networkx + plotly.
"""
import networkx as nx
import plotly.graph_objects as go


def build_attack_graph(incident_alerts_df):
    """
    incident_alerts_df: ordered rows (chain_position asc) for one incident.
    Builds a directed graph: user -> device -> resource(s) in chain order,
    with edges belonging to the incident marked as 'attack_path'.
    """
    G = nx.DiGraph()

    if incident_alerts_df.empty:
        return G

    user_id = incident_alerts_df.iloc[0]["user_id"]
    device_id = incident_alerts_df.iloc[0]["device_id"]

    G.add_node(user_id, node_type="user")
    G.add_node(device_id, node_type="device")
    G.add_edge(user_id, device_id, attack_path=True)

    prev_node = device_id
    for _, row in incident_alerts_df.iterrows():
        resource = row["resource"]
        G.add_node(resource, node_type="resource",
                   attack_type=row["predicted_attack_type"],
                   risk_score=row["risk_score"])
        G.add_edge(prev_node, resource, attack_path=True,
                   attack_type=row["predicted_attack_type"])
        prev_node = resource

    return G


def render_graph_plotly(G):
    """Converts a networkx DiGraph into a plotly figure with attack-path
    edges in red and normal nodes in blue/gray."""
    if len(G.nodes) == 0:
        return go.Figure()

    pos = nx.spring_layout(G, seed=42, k=1.2)

    edge_x, edge_y = [], []
    for u, v, data in G.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=3, color="crimson"),
        hoverinfo="none",
        mode="lines"
    )

    node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
    color_map = {"user": "#4C9AFF", "device": "#FFAB00", "resource": "#DE350B"}

    for node, data in G.nodes(data=True):
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        ntype = data.get("node_type", "resource")
        label = f"{node}<br>type: {ntype}"
        if "attack_type" in data:
            label += f"<br>attack: {data['attack_type']}<br>risk: {data.get('risk_score', 0):.1f}"
        node_text.append(label)
        node_color.append(color_map.get(ntype, "#999999"))
        node_size.append(28 if ntype != "resource" else 22)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        text=[n for n in G.nodes()],
        textposition="bottom center",
        hovertext=node_text,
        hoverinfo="text",
        marker=dict(size=node_size, color=node_color, line=dict(width=2, color="white"))
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        showlegend=False,
        margin=dict(l=10, r=10, t=10, b=10),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=450,
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)"
    )
    return fig