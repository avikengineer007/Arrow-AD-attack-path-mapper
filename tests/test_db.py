"""Tests for SQLite database persistence."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import networkx as nx
import pytest

from arrow.db import get_connection, get_db_counts, init_db, load_graph, save_graph
from arrow.graph import add_ad_edge, add_ad_node, create_empty_graph


def test_init_db(tmp_path: Path):
    db_file = tmp_path / "test.db"
    init_db(db_file)
    assert db_file.exists()

    with get_connection(db_file) as conn:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row["name"] for row in cursor.fetchall()}
        assert "nodes" in tables
        assert "edges" in tables


def test_save_and_load_graph(tmp_path: Path):
    db_file = tmp_path / "graph.db"
    G = create_empty_graph()

    # Add sample nodes
    add_ad_node(G, "S-1", "User", "Alice", {"admincount": True, "department": "Security"})
    add_ad_node(G, "S-2", "Group", "Domain Admins", {"highvalue": True})
    add_ad_node(G, "S-3", "Computer", "DC01", {"os": "Windows Server 2022"})

    # Add sample edges
    add_ad_edge(G, "S-1", "S-2", "MemberOf", {"weight": 1})
    add_ad_edge(G, "S-2", "S-3", "AdminTo", {"weight": 2})

    n_count, e_count = save_graph(G, db_file)
    assert n_count == 3
    assert e_count == 2

    # Verify counts in DB
    counts = get_db_counts(db_file)
    assert counts["total_nodes"] == 3
    assert counts["total_edges"] == 2
    assert counts["nodes_by_type"] == {"User": 1, "Group": 1, "Computer": 1}
    assert counts["edges_by_type"] == {"MemberOf": 1, "AdminTo": 1}

    # Load back into a new MultiDiGraph
    loaded_G = load_graph(db_file)
    assert loaded_G.number_of_nodes() == 3
    assert loaded_G.number_of_edges() == 2

    # Check node attributes
    alice = loaded_G.nodes["S-1"]
    assert alice["name"] == "Alice"
    assert alice["type"] == "User"
    assert alice["properties"]["admincount"] is True
    assert alice["properties"]["department"] == "Security"

    # Check edge attributes
    edge_data = loaded_G.get_edge_data("S-1", "S-2", "MemberOf")
    assert edge_data["edge_type"] == "MemberOf"
    assert edge_data["properties"]["weight"] == 1


def test_load_graph_nonexistent(tmp_path: Path):
    missing_file = tmp_path / "missing.db"
    with pytest.raises(FileNotFoundError):
        load_graph(missing_file)


def test_get_db_counts_nonexistent(tmp_path: Path):
    missing_file = tmp_path / "missing.db"
    with pytest.raises(FileNotFoundError):
        get_db_counts(missing_file)

