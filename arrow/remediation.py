"""
Remediation and minimum edge-cut analysis for Active Directory attack paths.

Computes high-leverage edge cuts and bottleneck interventions to sever
privilege escalation paths toward high-value targets (e.g. Domain Admins).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import networkx as nx

from arrow.explain import get_edge_explanation
from arrow.queries import resolve_node


@dataclass
class RemediationItem:
    """A recommended edge remediation step."""

    rank: int
    source: dict[str, Any]
    edge_type: str
    target: dict[str, Any]
    paths_eliminated: int
    paths_eliminated_pct: float
    remediation: str
    mitre_id: str
    noise_score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "rank": self.rank,
            "source": self.source,
            "relationship": self.edge_type,
            "target": self.target,
            "paths_eliminated": self.paths_eliminated,
            "paths_eliminated_pct": round(self.paths_eliminated_pct, 1),
            "remediation": self.remediation,
            "mitre_id": self.mitre_id,
            "noise_score": round(self.noise_score, 1),
        }


@dataclass
class RemediationPlan:
    """Complete remediation plan for disconnecting paths to a target."""

    target: dict[str, Any]
    sources: list[dict[str, Any]]
    total_paths_identified: int
    algorithm: str
    items: list[RemediationItem] = field(default_factory=list)
    paths_remaining: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "sources": self.sources,
            "total_paths_identified": self.total_paths_identified,
            "algorithm": self.algorithm,
            "paths_remaining": self.paths_remaining,
            "recommendations": [item.to_dict() for item in self.items],
        }


def generate_remediation_advice(
    source_name: str,
    source_type: str,
    edge_type: str,
    target_name: str,
    target_type: str,
) -> str:
    """Generate plain-language, actionable remediation guidance for an edge."""
    s_clean = source_name.split("@")[0]
    t_clean = target_name.split("@")[0]

    if edge_type == "MemberOf":
        return f"Remove '{s_clean}' from group '{t_clean}' to eliminate inherited administrative privileges."

    if edge_type == "AdminTo":
        return f"Remove '{s_clean}' from the local Administrators group on computer '{t_clean}'."

    if edge_type == "HasSession":
        return (
            f"Terminate active/disconnected session of '{t_clean}' on host '{s_clean}'; "
            "enable LAPS, Restricted Admin mode, and Credential Guard."
        )

    if edge_type == "GenericAll":
        return (
            f"Remove GenericAll Access Control Entry (ACE) granted to '{s_clean}' on '{t_clean}' DACL; "
            "enforce principle of least privilege."
        )

    if edge_type == "GenericWrite":
        return f"Revoke GenericWrite rights for '{s_clean}' on '{t_clean}'; restrict attribute modifications."

    if edge_type == "WriteDacl":
        return f"Revoke WriteDacl permission for '{s_clean}' on '{t_clean}' security descriptor."

    if edge_type == "WriteOwner":
        return f"Revoke WriteOwner permission for '{s_clean}' on '{t_clean}'; reset object owner to Protected Users."

    if edge_type == "ForceChangePassword":
        return f"Revoke ForceChangePassword (Reset Password) extended right granted to '{s_clean}' on '{t_clean}'."

    if edge_type == "AddMember":
        return f"Revoke AddMember (Write Property - Member) right for '{s_clean}' on group '{t_clean}'."

    if edge_type == "Owns":
        return f"Transfer object ownership of '{t_clean}' away from '{s_clean}' to Domain Admins or Tier-0 admin."

    if edge_type == "CanRDP":
        return f"Remove '{s_clean}' from Remote Desktop Users group on host '{t_clean}'."

    if edge_type == "AllowedToDelegate":
        return (
            f"Disable unconstrained/constrained delegation on '{s_clean}'; "
            "migrate to Resource-Based Constrained Delegation (RBCD) with restricted SPNs."
        )

    if edge_type == "AllowedToAct":
        return f"Clear msDS-AllowedToActOnBehalfOfOtherIdentity attribute on '{t_clean}' to revoke RBCD access for '{s_clean}'."

    if edge_type == "DCSync":
        return f"Revoke DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights on domain root for '{s_clean}'."

    if edge_type == "SQLAdmin":
        return f"Revoke sysadmin role and disable xp_cmdshell for '{s_clean}' on MSSQL instance '{t_clean}'."

    if edge_type == "ADCSEnroll":
        return (
            f"Revoke enrollment rights for '{s_clean}' on certificate template '{t_clean}', or disable "
            "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and enforce CA manager approval (remediate ESC1)."
        )

    if edge_type == "ADCSVulnerableTemplate":
        return (
            f"Remove write/DACL modification permissions for '{s_clean}' on certificate template '{t_clean}' "
            "security descriptor to prevent template overwrite (remediate ESC4)."
        )

    if edge_type == "ADCSHostRelay":
        return (
            f"Disable HTTP Web Enrollment (/certsrv/) on Enterprise CA '{t_clean}', or enforce HTTPS and "
            "Extended Protection for Authentication (EPA) to prevent NTLM relay (remediate ESC8)."
        )

    return f"Remove or restrict relationship '{edge_type}' from '{s_clean}' to '{t_clean}'."


def compute_remediation_plan(
    graph: nx.MultiDiGraph,
    target: str,
    source: str | None = None,
    max_recommendations: int = 10,
    path_cutoff: int = 8,
) -> RemediationPlan:
    """
    Compute a prioritized set of edge remediations to sever attack paths to target.

    ### Algorithm Architecture & Theoretical Rationale:
    NetworkX provides `minimum_edge_cut(G, s, t)` for single source-target pairs.
    However, in real Active Directory security modeling:
    1. There are multiple potential initial compromise sources (all owned principals or
       low-privilege domain users) converging on a high-value target (e.g. Domain Admins).
    2. A naive multi-source min-cut (via a super-source with infinite capacity) often selects
       the immediate inbound edges of the target (e.g., disconnecting legitimate administrators
       from the Domain Admins group), rather than resolving the upstream privilege escalations.
    3. Finding the minimal set of edges to break a set of attack paths is isomorphic to the
       **Hitting Set Problem** (NP-hard). We utilize **Greedy Maximum Path Elimination**,
       the canonical polynomial-time approximation algorithm with an O(ln |P|) approximation
       guarantee: at each iteration, the edge that severs the highest number of active remaining
       attack paths is greedily chosen and removed from the active path set.

    Args:
        graph: NetworkX MultiDiGraph of Active Directory.
        target: Target name or SID (e.g. 'Domain Admins').
        source: Optional specific starting principal. If None, considers owned nodes or
                all ancestor nodes capable of reaching the target.
        max_recommendations: Maximum number of remediation edges to return.
        path_cutoff: Maximum hop depth to explore paths.

    Returns:
        RemediationPlan with ranked edge fixes and path elimination metrics.
    """
    target_id = resolve_node(graph, target)
    if not target_id:
        raise ValueError(f"Target node '{target}' could not be resolved.")

    target_data = graph.nodes[target_id]
    target_dict = {
        "objectid": target_id,
        "name": target_data.get("name", target_id),
        "type": target_data.get("type", "Unknown"),
    }

    # 1. Determine candidate source nodes
    candidate_sources: list[str] = []
    if source is not None:
        src_id = resolve_node(graph, source)
        if not src_id:
            raise ValueError(f"Source node '{source}' could not be resolved.")
        candidate_sources = [src_id]
    else:
        # Check for owned nodes first
        owned_candidates = [
            nid for nid, d in graph.nodes(data=True)
            if (d.get("owned") is True or d.get("properties", {}).get("owned") is True) and nid != target_id
        ]
        if owned_candidates:
            candidate_sources = owned_candidates
        else:
            # If no owned nodes, consider all non-target ancestor nodes that can reach target
            ancestors = nx.ancestors(graph, target_id)
            # Prioritize Users and Computers as realistic entry principals
            principals = [
                nid for nid in ancestors
                if graph.nodes[nid].get("type") in ("User", "Computer")
            ]
            candidate_sources = principals if principals else list(ancestors)

    if not candidate_sources:
        return RemediationPlan(
            target=target_dict,
            sources=[],
            total_paths_identified=0,
            algorithm="Greedy Maximum Path Elimination (Hitting Set Approximation)",
            items=[],
            paths_remaining=0,
        )

    sources_info = [
        {
            "objectid": s,
            "name": graph.nodes[s].get("name", s),
            "type": graph.nodes[s].get("type", "Unknown"),
        }
        for s in candidate_sources[:20]  # Cap for presentation if broad
    ]

    # 2. Collect attack paths from sources to target
    # Each path is represented as a tuple of edge identifiers: ((u, v, etype), ...)
    collected_paths: list[list[tuple[str, str, str]]] = []

    # To avoid combinatorial path explosion on dense cliques, use bounded path search
    for s_id in candidate_sources:
        if not nx.has_path(graph, s_id, target_id):
            continue

        try:
            # Gather shortest and alternate paths
            # 1. All shortest paths
            for sp in nx.all_shortest_paths(graph, s_id, target_id):
                edge_path: list[tuple[str, str, str]] = []
                for i in range(len(sp) - 1):
                    u, v = sp[i], sp[i + 1]
                    # Pick the primary edge
                    edge_candidates = list(graph[u][v].values())
                    etype = edge_candidates[0].get("edge_type", "Unknown")
                    edge_path.append((u, v, etype))
                if edge_path and edge_path not in collected_paths:
                    collected_paths.append(edge_path)

            # 2. Additional simple paths up to cutoff
            count = 0
            for p in nx.all_simple_paths(graph, s_id, target_id, cutoff=path_cutoff):
                edge_path = []
                for i in range(len(p) - 1):
                    u, v = p[i], p[i + 1]
                    edge_candidates = list(graph[u][v].values())
                    etype = edge_candidates[0].get("edge_type", "Unknown")
                    edge_path.append((u, v, etype))
                if edge_path and edge_path not in collected_paths:
                    collected_paths.append(edge_path)
                    count += 1
                if count >= 15:
                    break
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue

    total_paths = len(collected_paths)
    if total_paths == 0:
        return RemediationPlan(
            target=target_dict,
            sources=sources_info,
            total_paths_identified=0,
            algorithm="Greedy Maximum Path Elimination (Hitting Set Approximation)",
            items=[],
            paths_remaining=0,
        )

    # 3. Greedy Maximum Coverage / Hitting Set Algorithm
    # Active paths remaining to be severed
    active_paths: list[set[tuple[str, str, str]]] = [set(p) for p in collected_paths]
    remediation_items: list[RemediationItem] = []
    chosen_edges: set[tuple[str, str, str]] = set()

    for rank in range(1, max_recommendations + 1):
        if not active_paths:
            break

        # Calculate edge frequency across remaining active paths
        edge_counts: dict[tuple[str, str, str], int] = {}
        for p in active_paths:
            for edge in p:
                if edge not in chosen_edges:
                    edge_counts[edge] = edge_counts.get(edge, 0) + 1

        if not edge_counts:
            break

        # Find edge that eliminates the maximum number of active paths
        # Tie-breaker: prefer higher noise_score or non-target-inbound edges
        best_edge, eliminated_count = max(
            edge_counts.items(),
            key=lambda item: (item[1], 0 if item[0][1] == target_id else 1),
        )

        chosen_edges.add(best_edge)
        u, v, etype = best_edge

        src_node = graph.nodes.get(u, {})
        dst_node = graph.nodes.get(v, {})
        src_name = str(src_node.get("name", u))
        src_type = str(src_node.get("type", "Unknown"))
        dst_name = str(dst_node.get("name", v))
        dst_type = str(dst_node.get("type", "Unknown"))

        advice = generate_remediation_advice(
            source_name=src_name,
            source_type=src_type,
            edge_type=etype,
            target_name=dst_name,
            target_type=dst_type,
        )
        expl = get_edge_explanation(etype)

        pct = (eliminated_count / total_paths * 100) if total_paths > 0 else 0.0

        item = RemediationItem(
            rank=rank,
            source={"objectid": u, "name": src_name, "type": src_type},
            edge_type=etype,
            target={"objectid": v, "name": dst_name, "type": dst_type},
            paths_eliminated=eliminated_count,
            paths_eliminated_pct=pct,
            remediation=advice,
            mitre_id=expl.mitre_id,
            noise_score=expl.noise_score,
        )
        remediation_items.append(item)

        # Remove all paths that contained this edge
        active_paths = [p for p in active_paths if best_edge not in p]

    return RemediationPlan(
        target=target_dict,
        sources=sources_info,
        total_paths_identified=total_paths,
        algorithm="Greedy Maximum Path Elimination (Hitting Set Approximation)",
        items=remediation_items,
        paths_remaining=len(active_paths),
    )
