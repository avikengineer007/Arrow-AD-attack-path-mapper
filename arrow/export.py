"""
Export Active Directory attack-path graphs to Graphviz DOT and Mermaid formats.
"""

from __future__ import annotations

import re
from typing import Any
import networkx as nx

from arrow.queries import resolve_node

NODE_SHAPES_DOT: dict[str, str] = {
    "User": "ellipse",
    "Group": "box",
    "Computer": "component",
    "Domain": "hexagon",
    "GPO": "note",
    "OU": "folder",
}

NODE_COLORS_DOT: dict[str, str] = {
    "User": "#4FC3F7",
    "Group": "#FFD54F",
    "Computer": "#81C784",
    "Domain": "#E57373",
    "GPO": "#BA68C8",
    "OU": "#B0BEC5",
}


def sanitize_id(identifier: str) -> str:
    """Sanitize an identifier for DOT and Mermaid node IDs."""
    clean = re.sub(r"[^a-zA-Z0-9_]", "_", str(identifier))
    if not clean or clean[0].isdigit():
        clean = "n_" + clean
    return clean


def escape_dot_string(value: str) -> str:
    """Escape quotes, backslashes, and control characters for Graphviz DOT string literals."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "")


def escape_mermaid_label(value: str) -> str:
    """Escape structural characters that break Mermaid flowchart node/edge syntax."""
    return (
        str(value)
        .replace('"', "'")
        .replace("[", "(")
        .replace("]", ")")
        .replace("|", "/")
        .replace("\n", "<br/>")
    )


def extract_key_paths_subgraph(
    graph: nx.MultiDiGraph,
    target: str | None = None,
    source: str | None = None,
    max_nodes: int = 50,
) -> nx.MultiDiGraph:
    """
    Extract a focused subgraph containing the most critical attack paths.

    If target is provided, extracts all paths from owned nodes (or all sources)
    to target up to max_nodes. Otherwise extracts connected components of interest.
    """
    sub = nx.MultiDiGraph()

    if target:
        target_id = resolve_node(graph, target)
        if target_id:
            # Gather sources
            candidate_sources: list[str] = []
            if source:
                s_id = resolve_node(graph, source)
                if s_id:
                    candidate_sources = [s_id]
            else:
                owned = [
                    nid for nid, d in graph.nodes(data=True)
                    if d.get("owned") is True or d.get("properties", {}).get("owned") is True
                ]
                if owned:
                    candidate_sources = owned
                else:
                    ancestors = nx.ancestors(graph, target_id)
                    candidate_sources = [
                        nid for nid in ancestors
                        if graph.nodes[nid].get("type") in ("User", "Computer")
                    ][:5]

            selected_nodes: set[str] = {target_id}
            selected_edges: list[tuple[str, str, str, dict[str, Any]]] = []

            for s_id in candidate_sources:
                if not nx.has_path(graph, s_id, target_id):
                    continue
                try:
                    for path in nx.all_shortest_paths(graph, s_id, target_id):
                        if len(selected_nodes) + len(path) > max_nodes:
                            break
                        selected_nodes.update(path)
                        for i in range(len(path) - 1):
                            u, v = path[i], path[i + 1]
                            for key, edata in graph[u][v].items():
                                selected_edges.append((u, v, key, edata))
                                break
                except Exception:
                    continue

            for nid in selected_nodes:
                sub.add_node(nid, **graph.nodes[nid])
            for u, v, key, edata in selected_edges:
                sub.add_edge(u, v, key=key, **edata)

            if len(sub.nodes) > 0:
                return sub

    # Default fallback: take top 30 most-connected nodes
    degrees = sorted(graph.degree(), key=lambda x: x[1], reverse=True)[:max_nodes]
    top_nodes = {nid for nid, _ in degrees}

    for nid in top_nodes:
        sub.add_node(nid, **graph.nodes[nid])
    for u, v, key, edata in graph.edges(keys=True, data=True):
        if u in top_nodes and v in top_nodes:
            sub.add_edge(u, v, key=key, **edata)

    return sub


def export_to_dot(
    graph: nx.MultiDiGraph,
    title: str = "Arrow Active Directory Attack Graph",
) -> str:
    """Generate Graphviz DOT formatted diagram string with properly escaped attributes."""
    safe_title = escape_dot_string(title)
    lines: list[str] = [
        f'digraph "{safe_title}" {{',
        '    graph [rankdir=LR, bgcolor="#1E1E2E", fontname="Helvetica,Arial,sans-serif", fontcolor="#CDD6F4"];',
        '    node [style="filled,rounded", fontname="Helvetica,Arial,sans-serif", fontcolor="#11111B", fontsize=10];',
        '    edge [fontname="Helvetica,Arial,sans-serif", fontsize=9, fontcolor="#A6ADC8", color="#89B4FA", arrowsize=0.8];',
        "",
    ]

    id_map: dict[str, str] = {}
    for idx, (nid, data) in enumerate(graph.nodes(data=True)):
        dot_id = f"node_{idx}_{sanitize_id(nid)}"
        id_map[nid] = dot_id

        ntype = str(data.get("type", "Unknown"))
        name = str(data.get("name", nid)).split("@")[0]
        shape = NODE_SHAPES_DOT.get(ntype, "ellipse")
        fillcolor = NODE_COLORS_DOT.get(ntype, "#CBA6F7")

        is_owned = data.get("owned") is True or data.get("properties", {}).get("owned") is True
        border = 'color="#F38BA8", penwidth=3.0' if is_owned else 'color="#313244", penwidth=1.0'

        safe_name = escape_dot_string(name)
        safe_ntype = escape_dot_string(ntype)
        label = f"{safe_name}\\n({safe_ntype})"
        lines.append(f'    {dot_id} [label="{label}", shape={shape}, fillcolor="{fillcolor}", {border}];')

    lines.append("")

    for u, v, data in graph.edges(data=True):
        src_id = id_map.get(u)
        dst_id = id_map.get(v)
        if not src_id or not dst_id:
            continue
        etype = str(data.get("edge_type", "Unknown"))
        safe_etype = escape_dot_string(etype)
        lines.append(f'    {src_id} -> {dst_id} [label=" {safe_etype} "];')

    lines.append("}")
    return "\n".join(lines)


def export_to_mermaid(
    graph: nx.MultiDiGraph,
    title: str | None = None,
) -> str:
    """Generate Mermaid flowchart LR formatted diagram string with sanitized labels."""
    lines: list[str] = [
        "flowchart LR",
        "    %% Mermaid Attack Path Graph exported by Arrow",
        "    classDef user fill:#89dceb,stroke:#04a5e5,stroke-width:1.5px,color:#11111b;",
        "    classDef group fill:#f9e2af,stroke:#df8e1d,stroke-width:1.5px,color:#11111b;",
        "    classDef computer fill:#a6e3a1,stroke:#40a02b,stroke-width:1.5px,color:#11111b;",
        "    classDef domain fill:#f38ba8,stroke:#d20f39,stroke-width:2px,color:#11111b;",
        "    classDef owned fill:#fab387,stroke:#fe640b,stroke-width:3px,color:#11111b;",
        "",
    ]

    id_map: dict[str, str] = {}
    type_classes: dict[str, list[str]] = {
        "user": [],
        "group": [],
        "computer": [],
        "domain": [],
        "owned": [],
    }

    for idx, (nid, data) in enumerate(graph.nodes(data=True)):
        m_id = f"n{idx}_{sanitize_id(nid)[:12]}"
        id_map[nid] = m_id

        ntype = str(data.get("type", "Unknown"))
        name = str(data.get("name", nid)).split("@")[0]
        safe_name = escape_mermaid_label(name)
        safe_ntype = escape_mermaid_label(ntype)
        is_owned = data.get("owned") is True or data.get("properties", {}).get("owned") is True

        label = f'"{safe_name}<br/>({safe_ntype})"'
        lines.append(f"    {m_id}[{label}]")

        t_lower = ntype.lower()
        if is_owned:
            type_classes["owned"].append(m_id)
        elif t_lower in type_classes:
            type_classes[t_lower].append(m_id)

    lines.append("")

    for u, v, data in graph.edges(data=True):
        src = id_map.get(u)
        dst = id_map.get(v)
        if not src or not dst:
            continue
        etype = str(data.get("edge_type", "Unknown"))
        safe_etype = escape_mermaid_label(etype)
        lines.append(f"    {src} -->|{safe_etype}| {dst}")

    lines.append("")
    for cname, members in type_classes.items():
        if members:
            lines.append(f"    class {','.join(members)} {cname};")

    return "\n".join(lines)

