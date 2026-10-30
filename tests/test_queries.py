"""Unit tests for arrow/queries.py query functions."""

from __future__ import annotations

import networkx as nx
import pytest

from arrow.db import load_graph, save_graph
from arrow.graph import add_ad_edge, add_ad_node, create_empty_graph
from arrow.queries import (
    STEALTH_WEIGHTS,
    compute_blast_radius,
    find_path,
    list_owned_nodes,
    mark_node_owned,
    resolve_node,
    run_named_query,
)
from arrow.sample_data import build_synthetic_dataset, write_sample_zip
from arrow.ingest.bloodhound import BloodHoundImporter


@pytest.fixture
def sample_graph(tmp_path) -> tuple[nx.MultiDiGraph, str]:
    """Provide a loaded graph from the synthetic dataset and its SQLite db path."""
    zip_path = tmp_path / "sample.zip"
    write_sample_zip(zip_path)

    importer = BloodHoundImporter()
    graph = importer.import_path(zip_path)

    db_path = tmp_path / "test.db"
    save_graph(graph, db_path)
    return graph, str(db_path)


def test_resolve_node(sample_graph):
    graph, _ = sample_graph

    # Exact SID
    sid = "S-1-5-21-1111111111-2222222222-3333333333-1202"
    assert resolve_node(graph, sid) == sid

    # Exact Name
    assert resolve_node(graph, "VICTIM_BOB@CORP.LOCAL") == sid

    # Short prefix name
    assert resolve_node(graph, "victim_bob") == sid

    # Substring match (Domain Admins)
    da_sid = "S-1-5-21-1111111111-2222222222-3333333333-512"
    assert resolve_node(graph, "Domain Admins") == da_sid

    # Nonexistent node
    assert resolve_node(graph, "NONEXISTENT_USER") is None


def test_mark_and_list_owned(sample_graph):
    graph, db_path = sample_graph
    bob_sid = "S-1-5-21-1111111111-2222222222-3333333333-1202"

    # Initially not owned
    assert len(list_owned_nodes(graph)) == 0

    # Mark as owned
    res = mark_node_owned(graph, db_path, "victim_bob", owned=True)
    assert res["owned"] is True
    assert res["objectid"] == bob_sid

    owned = list_owned_nodes(graph)
    assert len(owned) == 1
    assert owned[0]["objectid"] == bob_sid

    # Verify persisted in database by reloading
    reloaded_g = load_graph(db_path)
    reloaded_owned = list_owned_nodes(reloaded_g)
    assert len(reloaded_owned) == 1
    assert reloaded_owned[0]["objectid"] == bob_sid

    # Unmark as owned
    res_un = mark_node_owned(graph, db_path, "victim_bob", owned=False)
    assert res_un["owned"] is False
    assert len(list_owned_nodes(graph)) == 0


def test_find_path_planted_path(sample_graph):
    graph, _ = sample_graph

    # Planted path: victim_bob -> Help Desk -> PIVOT-SRV -> TARGET-SRV
    result = find_path(graph, start="victim_bob", target="TARGET-SRV", stealth=False)
    assert result.hops == 3
    assert result.start["name"] == "VICTIM_BOB@CORP.LOCAL"
    assert result.target["name"] == "TARGET-SRV.CORP.LOCAL"

    chain = result.chain
    assert "VICTIM_BOB@CORP.LOCAL ──[MemberOf]──> HELP DESK@CORP.LOCAL" in chain
    assert "──[GenericAll]──> PIVOT-SRV.CORP.LOCAL" in chain
    assert "──[AdminTo]──> TARGET-SRV.CORP.LOCAL" in chain

    # Test path resolution to "Domain Admins"
    da_result = find_path(graph, start="victim_bob", target="Domain Admins", stealth=False)
    assert da_result.hops == 5
    assert da_result.target["name"] == "DOMAIN ADMINS@CORP.LOCAL"


def test_find_path_from_owned_node(sample_graph):
    graph, db_path = sample_graph

    # When no owned node and start is None, raises ValueError
    with pytest.raises(ValueError, match="no owned nodes found"):
        find_path(graph, start=None, target="TARGET-SRV")

    # Mark victim_bob as owned
    mark_node_owned(graph, db_path, "victim_bob", owned=True)

    # Now compute path with start=None -> uses owned victim_bob
    result = find_path(graph, start=None, target="TARGET-SRV")
    assert result.hops == 3
    assert result.start["name"] == "VICTIM_BOB@CORP.LOCAL"
    assert result.target["name"] == "TARGET-SRV.CORP.LOCAL"


def test_stealth_vs_unweighted_path():
    """Verify that stealth path favors quiet relationships over noisy direct shortcuts."""
    G = create_empty_graph()
    add_ad_node(G, "ATTACKER", "User", "Attacker")
    add_ad_node(G, "INTERMEDIATE", "Group", "StagingGroup")
    add_ad_node(G, "TARGET", "Computer", "TargetServer")

    # Path 1 (Noisy shortcut: 1 hop, HasSession weight = 8.0)
    add_ad_edge(G, "ATTACKER", "TARGET", "HasSession")

    # Path 2 (Quiet multi-hop: 2 hops, MemberOf 1.0 + GenericAll 1.0 = 2.0)
    add_ad_edge(G, "ATTACKER", "INTERMEDIATE", "MemberOf")
    add_ad_edge(G, "INTERMEDIATE", "TARGET", "GenericAll")

    # Unweighted shortest path chooses 1-hop noisy path
    unweighted_res = find_path(G, start="ATTACKER", target="TARGET", stealth=False)
    assert unweighted_res.hops == 1
    assert unweighted_res.segments[0].edge_type == "HasSession"

    # Stealth path chooses 2-hop quiet path because weight 2.0 < 8.0
    stealth_res = find_path(G, start="ATTACKER", target="TARGET", stealth=True)
    assert stealth_res.hops == 2
    assert stealth_res.total_weight == 2.0
    assert stealth_res.segments[0].edge_type == "MemberOf"
    assert stealth_res.segments[1].edge_type == "GenericAll"


def test_compute_blast_radius(sample_graph):
    graph, _ = sample_graph

    blast = compute_blast_radius(graph, user_or_group="victim_bob", to_da=True)
    assert blast["total_reachable"] == 14
    assert blast["max_hops"] == 6
    assert blast["reaches_domain_admins"] is True

    # Check that Hop 1 contains HELP DESK
    hop1_names = [item["name"] for item in blast["hops"][1]]
    assert "HELP DESK@CORP.LOCAL" in hop1_names

    # Check DA path
    assert blast["da_path"] is not None
    assert len(blast["da_path"]) == 5


def test_named_queries(sample_graph):
    graph, _ = sample_graph

    # 1. kerberoastable
    kerb = run_named_query(graph, "kerberoastable")
    assert len(kerb) >= 1
    assert any(r["name"] == "USER_DAVE@CORP.LOCAL" for r in kerb)

    # 2. asrep
    asrep = run_named_query(graph, "asrep")
    assert len(asrep) >= 1
    assert any(r["name"] == "USER_EVE@CORP.LOCAL" for r in asrep)

    # 3. unconstrained
    uncon = run_named_query(graph, "unconstrained")
    assert len(uncon) >= 1
    assert any(r["name"] == "DC01.CORP.LOCAL" for r in uncon)

    # 4. dcsync
    dcsync = run_named_query(graph, "dcsync")
    assert len(dcsync) >= 1
    assert any(r["name"] == "DOMAIN ADMINS@CORP.LOCAL" for r in dcsync)

    # Invalid query
    with pytest.raises(ValueError, match="Unknown query"):
        run_named_query(graph, "nonexistent_query")

