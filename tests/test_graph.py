"""Tests for the graph model and stats computation."""

from __future__ import annotations

import networkx as nx
import pytest

from arrow.graph import (
    EDGE_TYPES,
    NODE_TYPES,
    add_ad_edge,
    add_ad_node,
    compute_graph_stats,
    create_empty_graph,
)


def test_schema_constants():
    expected_nodes = {"User", "Group", "Computer", "Domain", "GPO", "OU"}
    assert expected_nodes.issubset(NODE_TYPES)

    expected_edges = {
        "MemberOf",
        "AdminTo",
        "HasSession",
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "ForceChangePassword",
        "AddMember",
        "Owns",
        "CanRDP",
        "AllowedToDelegate",
        "AllowedToAct",
        "DCSync",
        "SQLAdmin",
        "ADCSEnroll",
        "ADCSVulnerableTemplate",
        "ADCSHostRelay",
    }
    assert expected_edges == EDGE_TYPES


def test_add_nodes_and_edges():
    G = create_empty_graph()
    add_ad_node(G, "U-1", "User", "Bob", {"enabled": True})
    add_ad_node(G, "G-1", "Group", "Admins")
    add_ad_edge(G, "U-1", "G-1", "MemberOf")

    assert G.has_node("U-1")
    assert G.has_node("G-1")
    assert G.has_edge("U-1", "G-1", key="MemberOf")
    assert G.nodes["U-1"]["name"] == "Bob"
    assert G.nodes["U-1"]["type"] == "User"


def test_add_edge_auto_creates_placeholder_nodes():
    G = create_empty_graph()
    add_ad_edge(G, "UNKNOWN-SRC", "UNKNOWN-DST", "GenericAll")

    assert G.has_node("UNKNOWN-SRC")
    assert G.has_node("UNKNOWN-DST")
    assert G.nodes["UNKNOWN-SRC"]["type"] == "Unknown"
    assert G.nodes["UNKNOWN-DST"]["type"] == "Unknown"

    # Upgrading placeholder with concrete node metadata
    add_ad_node(G, "UNKNOWN-SRC", "User", "PromotedUser")
    assert G.nodes["UNKNOWN-SRC"]["type"] == "User"
    assert G.nodes["UNKNOWN-SRC"]["name"] == "PromotedUser"


def test_compute_graph_stats():
    G = create_empty_graph()
    # Path: A -> B -> C
    add_ad_node(G, "A", "User", "UserA")
    add_ad_node(G, "B", "Group", "GroupB")
    add_ad_node(G, "C", "Computer", "ComputerC")
    add_ad_node(G, "ISO", "User", "IsolatedUser")

    add_ad_edge(G, "A", "B", "MemberOf")
    add_ad_edge(G, "B", "C", "AdminTo")

    stats = compute_graph_stats(G, top_n=2)
    assert stats["total_nodes"] == 4
    assert stats["total_edges"] == 2
    assert stats["nodes_by_type"] == {"User": 2, "Group": 1, "Computer": 1}
    assert stats["edges_by_type"] == {"MemberOf": 1, "AdminTo": 1}
    assert stats["isolated_nodes_count"] == 1
    assert stats["weakly_connected_components"] == 2  # {A, B, C} and {ISO}

    # Top degrees
    top_in = stats["top_in_degree"]
    assert len(top_in) == 2
    assert top_in[0]["degree"] == 1  # B or C has in-degree 1

