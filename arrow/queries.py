"""Active Directory attack-path queries, pathfinding, ownership, and analytics."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import networkx as nx

from arrow.db import get_owned_nodes_from_db, update_node_property

# Stealth weights for edge types
# Higher weight = noisier / higher risk of detection by SOC / EDR
# Lower weight = quiet LDAP queries or dormant directory relationships
STEALTH_WEIGHTS: dict[str, float] = {
    # Dormant directory relationships (Zero network activity on execution)
    "MemberOf": 1.0,
    # Quiet LDAP DACL/Attribute writes (No host endpoints contacted, low noise)
    "GenericAll": 1.0,
    "GenericWrite": 1.0,
    "WriteDacl": 1.0,
    "WriteOwner": 1.0,
    "Owns": 1.0,
    # Moderately noisy: Kerberos traffic to KDC
    "AllowedToDelegate": 1.5,
    "AllowedToAct": 1.5,
    # Security log generated on domain controllers:
    # Event ID 4724 (password reset attempt), Event ID 4728 (member added to group)
    "ForceChangePassword": 2.0,
    "AddMember": 2.0,
    # Network replication to Domain Controller (Event ID 4662, network anomaly detection)
    "DCSync": 3.0,
    # Direct network connection to database service (TDS on TCP 1433, auth logs)
    "SQLAdmin": 4.0,
    # Direct RPC/SMB connection to host, service creation, Event ID 4624/4672, Defender alerts
    "AdminTo": 5.0,
    # Interactive RDP connection (TCP 3389, Event ID 4624 Type 10, visible in terminal sessions)
    "CanRDP": 6.0,
    # Active credential extraction required (e.g. LSASS dump, Token manipulation; high EDR detection rate)
    "HasSession": 8.0,
    # ADCS: Certificate enrollment request via RPC / HTTP (Certificate request logged, moderate noise)
    "ADCSEnroll": 1.5,
    # ADCS: Quiet LDAP modification of certificate template attributes/DACL (ESC4)
    "ADCSVulnerableTemplate": 1.0,
    # ADCS: NTLM authentication relay to HTTP enrollment endpoint (ESC8)
    "ADCSHostRelay": 4.0,
}

DEFAULT_STEALTH_WEIGHT: float = 2.0

AVAILABLE_QUERIES: list[str] = [
    "kerberoastable",
    "asrep",
    "unconstrained",
    "dcsync",
    "esc1",
    "esc4",
    "esc8",
    "adcs",
]


def resolve_node(graph: nx.MultiDiGraph, query: str) -> str | None:
    """
    Resolve a user-provided string to a canonical node objectid in the graph.

    Matching strategy:
    1. Exact objectid (SID) match.
    2. Exact case-insensitive name match.
    3. Prefix / short-name match (e.g. 'victim_bob' matching 'VICTIM_BOB@CORP.LOCAL',
       'DC01' matching 'DC01.CORP.LOCAL').
    4. Case-insensitive substring match (e.g. 'Domain Admins' matching 'DOMAIN ADMINS@CORP.LOCAL').
    """
    clean = query.strip()
    if not clean:
        return None

    # 1. Exact objectid match
    if clean in graph:
        return clean

    clean_lower = clean.lower()

    exact_matches: list[str] = []
    prefix_matches: list[str] = []
    substring_matches: list[str] = []

    for nid, data in graph.nodes(data=True):
        name = str(data.get("name", "")).lower()
        if not name:
            continue

        # Exact name match
        if name == clean_lower:
            exact_matches.append(nid)
            continue

        # Prefix / short name match
        name_no_domain = name.split("@")[0].split(".")[0]
        query_no_domain = clean_lower.split("@")[0].split(".")[0]
        if name_no_domain == query_no_domain or name.startswith(clean_lower):
            prefix_matches.append(nid)
            continue

        # Substring match
        if clean_lower in name:
            substring_matches.append(nid)

    if exact_matches:
        return exact_matches[0]
    if prefix_matches:
        return prefix_matches[0]
    if substring_matches:
        return substring_matches[0]

    return None


def mark_node_owned(
    graph: nx.MultiDiGraph,
    db_path: str | Path,
    identifier: str,
    owned: bool = True,
) -> dict[str, Any]:
    """
    Flag or unflag a node as owned in memory and persist the change to SQLite.

    Args:
        graph: Loaded MultiDiGraph.
        db_path: Path to SQLite database.
        identifier: Name or SID of node.
        owned: True to mark owned, False to unmark.

    Returns:
        dict with node metadata.
    """
    node_id = resolve_node(graph, identifier)
    if not node_id:
        raise ValueError(f"Node '{identifier}' not found in graph.")

    # Update in-memory graph
    node_data = graph.nodes[node_id]
    props = dict(node_data.get("properties", {}))
    props["owned"] = owned
    node_data["owned"] = owned
    node_data["properties"] = props

    # Persist to database
    update_node_property(db_path, node_id, "owned", owned)

    return {
        "objectid": node_id,
        "name": node_data.get("name", node_id),
        "type": node_data.get("type", "Unknown"),
        "owned": owned,
    }


def list_owned_nodes(graph: nx.MultiDiGraph) -> list[dict[str, Any]]:
    """Return all nodes currently flagged as owned."""
    owned_list: list[dict[str, Any]] = []
    for nid, data in graph.nodes(data=True):
        is_owned = data.get("owned") is True or data.get("properties", {}).get("owned") is True
        if is_owned:
            owned_list.append({
                "objectid": nid,
                "name": data.get("name", nid),
                "type": data.get("type", "Unknown"),
                "properties": data.get("properties", {}),
            })
    return sorted(owned_list, key=lambda x: str(x["name"]))


@dataclass
class PathSegment:
    step: int
    source: dict[str, Any]
    edge_type: str
    target: dict[str, Any]
    weight: float
    detection_risk: str


@dataclass
class PathResult:
    start: dict[str, Any]
    target: dict[str, Any]
    hops: int
    total_weight: float
    stealth: bool
    chain: str
    segments: list[PathSegment] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "target": self.target,
            "hops": self.hops,
            "total_weight": round(self.total_weight, 2),
            "stealth": self.stealth,
            "chain": self.chain,
            "segments": [
                {
                    "step": s.step,
                    "source": s.source,
                    "edge_type": s.edge_type,
                    "target": s.target,
                    "weight": round(s.weight, 2),
                    "detection_risk": s.detection_risk,
                }
                for s in self.segments
            ],
        }


def _get_risk_label(weight: float) -> str:
    if weight <= 1.5:
        return "Low (Quiet / Directory Write)"
    if weight <= 3.5:
        return "Moderate (Audited Security Log / DC Traffic)"
    if weight <= 5.5:
        return "High (Network Service Logon / Host Control)"
    return "Critical (Interactive Session / EDR Alert)"


def find_path(
    graph: nx.MultiDiGraph,
    start: str | None,
    target: str,
    stealth: bool = False,
) -> PathResult:
    """
    Compute shortest or stealthiest attack path to target.

    Args:
        graph: Active Directory MultiDiGraph.
        start: Starting principal (Name or SID). If None, searches from ANY owned node.
        target: Target entity (Name or SID).
        stealth: If True, uses weighted Dijkstra where noisy edges have higher weight.

    Returns:
        PathResult containing structured segments and chain string.
    """
    target_id = resolve_node(graph, target)
    if not target_id:
        raise ValueError(f"Target node '{target}' could not be resolved.")

    # Determine candidate start node(s)
    if start is not None:
        start_id = resolve_node(graph, start)
        if not start_id:
            raise ValueError(f"Start node '{start}' could not be resolved.")
        candidate_starts = [start_id]
    else:
        candidate_starts = [
            nid for nid, d in graph.nodes(data=True)
            if d.get("owned") is True or d.get("properties", {}).get("owned") is True
        ]
        if not candidate_starts:
            raise ValueError(
                "No start node specified and no owned nodes found in the database. "
                "Use 'arrow mark owned <name>' first or pass a start node."
            )

    def _multi_weight_func(u: str, v: str, multi_edges: dict[str, Any]) -> float:
        # In NetworkX MultiDiGraph, 3rd argument is {key: edge_data}
        return min(
            STEALTH_WEIGHTS.get(edge_data.get("edge_type", ""), DEFAULT_STEALTH_WEIGHT)
            for edge_data in multi_edges.values()
        )

    best_start: str | None = None
    best_path: list[str] | None = None
    best_cost = float("inf")

    for s_id in candidate_starts:
        if s_id == target_id:
            best_start = s_id
            best_path = [s_id]
            best_cost = 0.0
            break

        try:
            if stealth:
                cost = nx.dijkstra_path_length(graph, s_id, target_id, weight=_multi_weight_func)
                p = nx.dijkstra_path(graph, s_id, target_id, weight=_multi_weight_func)
            else:
                cost = float(nx.shortest_path_length(graph, s_id, target_id))
                p = nx.shortest_path(graph, s_id, target_id)

            if cost < best_cost:
                best_cost = cost
                best_path = p
                best_start = s_id
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue

    if best_path is None or best_start is None:
        target_name = graph.nodes[target_id].get("name", target_id)
        origin_desc = f"'{start}'" if start else "any owned node"
        raise nx.NetworkXNoPath(f"No attack path found from {origin_desc} to '{target_name}'.")

    # Build detailed path segments
    segments: list[PathSegment] = []
    chain_parts: list[str] = [str(graph.nodes[best_path[0]].get("name", best_path[0]))]
    total_accumulated_weight = 0.0

    for i in range(len(best_path) - 1):
        u = best_path[i]
        v = best_path[i + 1]

        # Select the best edge between u and v
        edge_candidates = list(graph[u][v].values())
        if stealth:
            best_edge = min(
                edge_candidates,
                key=lambda e: STEALTH_WEIGHTS.get(e.get("edge_type", ""), DEFAULT_STEALTH_WEIGHT),
            )
        else:
            best_edge = edge_candidates[0]

        etype = best_edge.get("edge_type", "Unknown")
        eweight = STEALTH_WEIGHTS.get(etype, DEFAULT_STEALTH_WEIGHT) if stealth else 1.0
        total_accumulated_weight += eweight

        src_node = {
            "objectid": u,
            "name": graph.nodes[u].get("name", u),
            "type": graph.nodes[u].get("type", "Unknown"),
        }
        dst_node = {
            "objectid": v,
            "name": graph.nodes[v].get("name", v),
            "type": graph.nodes[v].get("type", "Unknown"),
        }

        segments.append(
            PathSegment(
                step=i + 1,
                source=src_node,
                edge_type=etype,
                target=dst_node,
                weight=eweight,
                detection_risk=_get_risk_label(STEALTH_WEIGHTS.get(etype, DEFAULT_STEALTH_WEIGHT)),
            )
        )

        chain_parts.append(f"──[{etype}]──> {dst_node['name']}")

    chain_str = " ".join(chain_parts)
    start_info = {
        "objectid": best_start,
        "name": graph.nodes[best_start].get("name", best_start),
        "type": graph.nodes[best_start].get("type", "Unknown"),
    }
    target_info = {
        "objectid": target_id,
        "name": graph.nodes[target_id].get("name", target_id),
        "type": graph.nodes[target_id].get("type", "Unknown"),
    }

    return PathResult(
        start=start_info,
        target=target_info,
        hops=len(segments),
        total_weight=total_accumulated_weight if stealth else float(len(segments)),
        stealth=stealth,
        chain=chain_str,
        segments=segments,
    )


def compute_blast_radius(
    graph: nx.MultiDiGraph,
    user_or_group: str,
    to_da: bool = False,
) -> dict[str, Any]:
    """
    Compute all nodes reachable via outbound attack paths from a principal.

    Groups reachable nodes by hop distance and detects if Domain Admins is reachable.
    """
    root_id = resolve_node(graph, user_or_group)
    if not root_id:
        raise ValueError(f"Principal '{user_or_group}' could not be resolved in graph.")

    lengths = nx.single_source_shortest_path_length(graph, root_id)

    # Group reachable nodes by hop
    hops_map: dict[int, list[dict[str, Any]]] = {}
    da_target: dict[str, Any] | None = None
    da_path: list[dict[str, Any]] | None = None

    for target_id, dist in lengths.items():
        if dist == 0:
            continue

        target_data = graph.nodes[target_id]
        t_name = str(target_data.get("name", target_id))
        t_type = str(target_data.get("type", "Unknown"))
        t_props = target_data.get("properties", {})

        # Find shortest path from root to target to identify incoming relationship
        p = nx.shortest_path(graph, root_id, target_id)
        parent_id = p[-2]
        edge_data = list(graph[parent_id][target_id].values())[0]
        in_edge = edge_data.get("edge_type", "Unknown")

        item = {
            "objectid": target_id,
            "name": t_name,
            "type": t_type,
            "incoming_edge": in_edge,
            "parent_id": parent_id,
            "parent_name": graph.nodes[parent_id].get("name", parent_id),
            "hop": dist,
            "is_highvalue": t_props.get("highvalue", False) or t_props.get("admincount", False),
        }

        hops_map.setdefault(dist, []).append(item)

        # Check for Domain Admins
        is_da = (
            "domain admin" in t_name.lower()
            or target_id.endswith("-512")
            or (t_type == "Group" and "admin" in t_name.lower() and t_props.get("highvalue"))
        )
        if is_da and (da_target is None or dist < da_target.get("hop", 999)):
            da_target = item
            # Calculate path to DA
            full_path_result = find_path(graph, root_id, target_id, stealth=False)
            da_path = [
                {
                    "step": s.step,
                    "source": s.source["name"],
                    "edge_type": s.edge_type,
                    "target": s.target["name"],
                }
                for s in full_path_result.segments
            ]

    # Sort each hop list by type, then name
    for d in hops_map:
        hops_map[d].sort(key=lambda x: (x["type"], x["name"]))

    root_info = {
        "objectid": root_id,
        "name": graph.nodes[root_id].get("name", root_id),
        "type": graph.nodes[root_id].get("type", "Unknown"),
    }

    return {
        "source": root_info,
        "total_reachable": len(lengths) - 1,
        "max_hops": max(lengths.values()) if len(lengths) > 1 else 0,
        "reaches_domain_admins": da_target is not None,
        "da_target": da_target,
        "da_path": da_path,
        "hops": hops_map,
    }


def run_named_query(graph: nx.MultiDiGraph, query_name: str) -> list[dict[str, Any]]:
    """
    Execute built-in named Active Directory assessment queries:
    - kerberoastable: User accounts with an SPN set and not disabled
    - asrep: User accounts with DONT_REQ_PREAUTH set (AS-REP roastable)
    - unconstrained: Computers configured with unconstrained Kerberos delegation
    - dcsync: Principals with DCSync replication rights on the domain
    """
    q = query_name.strip().lower()
    results: list[dict[str, Any]] = []

    if q == "kerberoastable":
        for nid, data in graph.nodes(data=True):
            if data.get("type") != "User":
                continue
            props = data.get("properties", {})
            enabled = props.get("enabled", True)
            if enabled is False:
                continue

            has_spn = props.get("hasspn") is True
            spn_list = props.get("serviceprincipalnames") or props.get("spntargets") or []
            if has_spn or (isinstance(spn_list, list) and len(spn_list) > 0):
                spn_str = ", ".join(spn_list) if isinstance(spn_list, list) and spn_list else "Enabled (SPN set)"
                results.append({
                    "objectid": nid,
                    "name": data.get("name", nid),
                    "type": "User",
                    "spn": spn_str,
                    "admincount": bool(props.get("admincount", False)),
                    "description": props.get("description", ""),
                })

    elif q in ("asrep", "asreproastable"):
        for nid, data in graph.nodes(data=True):
            if data.get("type") != "User":
                continue
            props = data.get("properties", {})
            enabled = props.get("enabled", True)
            if enabled is False:
                continue

            dont_req = props.get("dontreqpreauth") is True
            uac = props.get("useraccountcontrol")
            if isinstance(uac, int) and (uac & 0x400000 != 0):
                dont_req = True

            if dont_req:
                results.append({
                    "objectid": nid,
                    "name": data.get("name", nid),
                    "type": "User",
                    "dontreqpreauth": True,
                    "admincount": bool(props.get("admincount", False)),
                    "description": props.get("description", ""),
                })

    elif q in ("unconstrained", "unconstraineddelegation"):
        for nid, data in graph.nodes(data=True):
            if data.get("type") != "Computer":
                continue
            props = data.get("properties", {})
            if props.get("unconstraineddelegation") is True:
                results.append({
                    "objectid": nid,
                    "name": data.get("name", nid),
                    "type": "Computer",
                    "operatingsystem": props.get("operatingsystem", "Unknown"),
                    "highvalue": bool(props.get("highvalue", False)),
                    "description": props.get("description", ""),
                })

    elif q == "dcsync":
        # Find all principals having a DCSync edge to any Domain node
        seen_pairs: set[tuple[str, str]] = set()
        for u, v, edge_data in graph.edges(data=True):
            if edge_data.get("edge_type") == "DCSync":
                domain_node = graph.nodes[v]
                if domain_node.get("type") == "Domain":
                    pair_key = (u, v)
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)
                    principal_data = graph.nodes[u]
                    results.append({
                        "objectid": u,
                        "name": principal_data.get("name", u),
                        "type": principal_data.get("type", "Unknown"),
                        "domain": domain_node.get("name", v),
                        "right": "DCSync",
                    })

    elif q == "esc1":
        # ESC1: Certificate template allowing requester-supplied SAN + Client Authentication EKU + no manager approval
        for nid, data in graph.nodes(data=True):
            if data.get("type") != "CertTemplate":
                continue
            props = data.get("properties", {})
            if props.get("esc1_vulnerable") is True:
                # Find principals with enrollment rights
                enrollees = [
                    graph.nodes[u].get("name", u)
                    for u, v, edata in graph.in_edges(nid, data=True)
                    if edata.get("edge_type") == "ADCSEnroll"
                ]
                results.append({
                    "objectid": nid,
                    "name": data.get("name", nid),
                    "type": "CertTemplate",
                    "vulnerability": "ESC1 (Requester-Supplied SAN + Client Auth)",
                    "enrollee_supplies_san": True,
                    "client_auth": True,
                    "manager_approval": False,
                    "enrollees": ", ".join(enrollees) if enrollees else "Domain Users",
                    "ekus": ", ".join(props.get("ekus", ["Client Authentication"])),
                })

    elif q == "esc4":
        # ESC4: Certificate template with vulnerable ACLs allowing low-privilege principals to modify configuration
        for u, v, edge_data in graph.edges(data=True):
            etype = edge_data.get("edge_type")
            if etype in ("ADCSVulnerableTemplate", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner"):
                target_node = graph.nodes.get(v, {})
                if target_node.get("type") == "CertTemplate":
                    src_node = graph.nodes.get(u, {})
                    src_name = src_node.get("name", u)
                    # Exclude default DA/Enterprise Admins/SYSTEM to highlight actionable misconfigurations
                    if any(admin in src_name.lower() for admin in ("domain admin", "enterprise admin", "system", "administrator")):
                        continue
                    results.append({
                        "objectid": v,
                        "name": target_node.get("name", v),
                        "type": "CertTemplate",
                        "vulnerability": "ESC4 (Vulnerable Template ACL Overwrite)",
                        "principal": src_name,
                        "principal_type": src_node.get("type", "Unknown"),
                        "permission": etype,
                    })

    elif q == "esc8":
        # ESC8: NTLM Relay to HTTP ADCS Enrollment Endpoint (/certsrv/)
        for nid, data in graph.nodes(data=True):
            if data.get("type") != "EnterpriseCA":
                continue
            props = data.get("properties", {})
            if props.get("esc8_vulnerable") is True or props.get("web_enrollment_enabled") is True:
                endpoint = props.get("web_enrollment_url", f"http://{data.get('name', nid).split('@')[0]}/certsrv/")
                results.append({
                    "objectid": nid,
                    "name": data.get("name", nid),
                    "type": "EnterpriseCA",
                    "vulnerability": "ESC8 (NTLM Relay to HTTP Enrollment)",
                    "endpoint": endpoint,
                    "epa_enabled": bool(props.get("epa_enabled", False)),
                    "ssl_required": bool(props.get("ssl_required", False)),
                })

    elif q == "adcs":
        # Aggregated ADCS queries (ESC1 + ESC4 + ESC8)
        esc1_items = run_named_query(graph, "esc1")
        esc4_items = run_named_query(graph, "esc4")
        esc8_items = run_named_query(graph, "esc8")
        results.extend(esc1_items)
        results.extend(esc4_items)
        results.extend(esc8_items)

    else:
        raise ValueError(
            f"Unknown query '{query_name}'. Available named queries: {', '.join(AVAILABLE_QUERIES)}"
        )

    return sorted(results, key=lambda x: str(x["name"]))

