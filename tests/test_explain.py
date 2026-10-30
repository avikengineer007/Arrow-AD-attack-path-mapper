"""
Tests for Arrow's explain layer, MITRE ATT&CK mappings, and path persistence.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from arrow.cli import app
from arrow.db import get_saved_path, list_saved_paths, save_computed_path, save_graph
from arrow.explain import EDGE_EXPLANATIONS, explain_path, get_edge_explanation
from arrow.graph import EDGE_TYPES, create_empty_graph
from arrow.queries import PathResult, PathSegment, find_path

runner = CliRunner()


def test_every_schema_edge_type_has_valid_mitre_explanation() -> None:
    """
    Assert that every single edge type defined in arrow.graph.EDGE_TYPES
    has an explanation entry with non-empty fields and a valid MITRE ATT&CK ID.
    """
    mitre_id_regex = re.compile(r"^T\d{4}(\.\d{3})?$")

    assert len(EDGE_TYPES) == 18, f"Expected 18 edge types in schema, got {len(EDGE_TYPES)}"

    for edge_type in EDGE_TYPES:
        assert edge_type in EDGE_EXPLANATIONS, f"Missing explanation for schema edge type: '{edge_type}'"

        expl = EDGE_EXPLANATIONS[edge_type]
        assert expl.edge_type == edge_type

        # Verify descriptions and attack mechanics
        assert expl.description and len(expl.description.strip()) > 15, (
            f"Explanation description too short or empty for '{edge_type}'"
        )
        assert expl.technique and len(expl.technique.strip()) > 15, (
            f"Explanation technique too short or empty for '{edge_type}'"
        )
        assert expl.mitre_name and len(expl.mitre_name.strip()) > 3, (
            f"MITRE technique name missing for '{edge_type}'"
        )

        # Verify valid MITRE ATT&CK technique format (e.g. T1098, T1069.002)
        assert mitre_id_regex.match(expl.mitre_id), (
            f"Invalid MITRE ATT&CK ID format for '{edge_type}': '{expl.mitre_id}'"
        )

        # Verify positive noise score
        assert expl.noise_score > 0, f"Noise score must be positive for '{edge_type}'"


def test_get_edge_explanation_fallback() -> None:
    """Unknown edge types return a safe fallback explanation with valid MITRE ID."""
    expl = get_edge_explanation("NonExistentCustomEdge")
    assert expl.edge_type == "NonExistentCustomEdge"
    assert "NonExistentCustomEdge" in expl.description
    assert re.match(r"^T\d{4}(\.\d{3})?$", expl.mitre_id)


def test_explain_path_from_dataclass() -> None:
    """Test generating a narrative from a PathResult dataclass."""
    path_res = PathResult(
        start={"objectid": "S-1-USER", "name": "alice@CORP.LOCAL", "type": "User"},
        target={"objectid": "S-1-DA", "name": "Domain Admins@CORP.LOCAL", "type": "Group"},
        hops=2,
        total_weight=2.0,
        stealth=False,
        chain="alice@CORP.LOCAL ──[GenericAll]──> bob@CORP.LOCAL ──[AddMember]──> Domain Admins@CORP.LOCAL",
        segments=[
            PathSegment(
                step=1,
                source={"objectid": "S-1-USER", "name": "alice@CORP.LOCAL", "type": "User"},
                edge_type="GenericAll",
                target={"objectid": "S-2-USER", "name": "bob@CORP.LOCAL", "type": "User"},
                weight=1.0,
                detection_risk="Low",
            ),
            PathSegment(
                step=2,
                source={"objectid": "S-2-USER", "name": "bob@CORP.LOCAL", "type": "User"},
                edge_type="AddMember",
                target={"objectid": "S-1-DA", "name": "Domain Admins@CORP.LOCAL", "type": "Group"},
                weight=2.0,
                detection_risk="Moderate",
            ),
        ],
    )

    explained = explain_path(path_res, path_id=42)

    assert explained.path_id == 42
    assert explained.start_name == "alice@CORP.LOCAL"
    assert explained.target_name == "Domain Admins@CORP.LOCAL"
    assert explained.hops_count == 2
    assert explained.total_noise_score == 3.0  # GenericAll (1.0) + AddMember (2.0)
    assert len(explained.hops) == 2

    # Check attack chain summary
    assert "File and Directory Permissions Modification: Windows DACL (T1222.001)" in explained.attack_chain_summary
    assert "Account Manipulation: Additional Local or Domain Groups (T1098.001)" in explained.attack_chain_summary

    # Check serialization
    d = explained.to_dict()
    assert d["path_id"] == 42
    assert len(d["hops"]) == 2
    assert d["hops"][0]["mitre_id"] == "T1222.001"
    assert d["hops"][1]["mitre_id"] == "T1098.001"

    # Check Markdown report formatting
    md = explained.to_markdown()
    assert "# Active Directory Attack Path Narrative" in md
    assert "**Path ID**: #42" in md
    assert "alice@CORP.LOCAL" in md
    assert "Domain Admins@CORP.LOCAL" in md
    assert "T1222.001" in md
    assert "T1098.001" in md
    assert "## Defensive Recommendations" in md


def test_explain_path_from_chain_string() -> None:
    """Test generating a narrative from a textual chain representation."""
    chain_str = "attacker ──[AdminTo]──> WS01 ──[HasSession]──> admin_svc ──[DCSync]──> CORP.LOCAL"
    explained = explain_path({"chain": chain_str})

    assert explained.hops_count == 3
    assert len(explained.hops) == 3
    assert explained.hops[0].edge_type == "AdminTo"
    assert explained.hops[0].mitre_id == "T1021.002"
    assert explained.hops[1].edge_type == "HasSession"
    assert explained.hops[1].mitre_id == "T1003.001"
    assert explained.hops[2].edge_type == "DCSync"
    assert explained.hops[2].mitre_id == "T1003.006"
    assert explained.total_noise_score == 5.0 + 8.0 + 3.0  # 16.0


def test_sqlite_path_persistence(tmp_path: Path) -> None:
    """Test saving and retrieving attack paths in SQLite."""
    db_file = tmp_path / "test_paths.db"

    dummy_path = {
        "start": {"objectid": "U-1", "name": "attacker", "type": "User"},
        "target": {"objectid": "G-1", "name": "Domain Admins", "type": "Group"},
        "hops": 1,
        "total_weight": 1.0,
        "stealth": True,
        "chain": "attacker ──[AddMember]──> Domain Admins",
        "segments": [
            {
                "step": 1,
                "source": {"objectid": "U-1", "name": "attacker", "type": "User"},
                "edge_type": "AddMember",
                "target": {"objectid": "G-1", "name": "Domain Admins", "type": "Group"},
                "weight": 2.0,
                "detection_risk": "Moderate",
            }
        ],
    }

    path_id_1 = save_computed_path(db_file, dummy_path)
    assert path_id_1 == 1

    path_id_2 = save_computed_path(db_file, dummy_path)
    assert path_id_2 == 2

    # Lookup by numeric int
    fetched = get_saved_path(db_file, 1)
    assert fetched is not None
    assert fetched["path_id"] == 1
    assert fetched["start"]["name"] == "attacker"
    assert fetched["target"]["name"] == "Domain Admins"

    # Lookup by formatted string slugs
    fetched_slug = get_saved_path(db_file, "path-1")
    assert fetched_slug is not None
    assert fetched_slug["path_id"] == 1

    fetched_hash = get_saved_path(db_file, "#2")
    assert fetched_hash is not None
    assert fetched_hash["path_id"] == 2

    # Nonexistent lookup
    assert get_saved_path(db_file, 999) is None
    assert get_saved_path(db_file, "invalid-slug") is None

    # List saved paths
    recent = list_saved_paths(db_file)
    assert len(recent) == 2
    assert recent[0]["id"] == 2
    assert recent[1]["id"] == 1


@pytest.fixture
def populated_ad_db(tmp_path: Path) -> Path:
    """Create a test database with a planted attack path."""
    db_file = tmp_path / "ad_lab.db"
    g = create_empty_graph()

    g.add_node("U-BOB", objectid="U-BOB", type="User", name="bob", properties={"owned": True})
    g.add_node("G-HD", objectid="G-HD", type="Group", name="HelpDesk", properties={})
    g.add_node("U-SVC", objectid="U-SVC", type="User", name="svc_sql", properties={})
    g.add_node("C-SRV01", objectid="C-SRV01", type="Computer", name="SRV01.CORP.LOCAL", properties={})
    g.add_node("G-DA", objectid="G-DA", type="Group", name="Domain Admins", properties={})

    # bob -> HelpDesk -> svc_sql -> SRV01 -> Domain Admins
    g.add_edge("U-BOB", "G-HD", key="MemberOf", edge_type="MemberOf")
    g.add_edge("G-HD", "U-SVC", key="GenericAll", edge_type="GenericAll")
    g.add_edge("U-SVC", "C-SRV01", key="AdminTo", edge_type="AdminTo")
    g.add_edge("C-SRV01", "G-DA", key="DCSync", edge_type="DCSync")

    save_graph(g, db_file)
    return db_file


def test_cli_path_auto_saves_and_explain_command(populated_ad_db: Path) -> None:
    """Test full CLI workflow: arrow path auto-saves ID, then arrow explain generates narrative."""
    # Step 1: Run arrow path
    path_res = runner.invoke(
        app,
        ["path", "bob", "--to", "Domain Admins", "--db", str(populated_ad_db)],
    )
    assert path_res.exit_code == 0
    assert "Saved as Path ID:" in path_res.stdout or "Path ID" in path_res.stdout
    assert "arrow explain 1" in path_res.stdout

    # Step 2: Run arrow explain 1 (Default text / Rich format)
    explain_res = runner.invoke(
        app,
        ["explain", "1", "--db", str(populated_ad_db)],
    )
    assert explain_res.exit_code == 0
    assert "Active Directory Attack Path Narrative Explanation" in explain_res.stdout
    assert "Origin:" in explain_res.stdout
    assert "bob" in explain_res.stdout
    assert "Domain Admins" in explain_res.stdout
    assert "MITRE ATT&CK:" in explain_res.stdout
    assert "T1069.002" in explain_res.stdout  # MemberOf
    assert "T1222.001" in explain_res.stdout  # GenericAll
    assert "T1021.002" in explain_res.stdout  # AdminTo
    assert "T1003.006" in explain_res.stdout  # DCSync
    assert "Attack Chain Summary" in explain_res.stdout

    # Step 3: Run arrow explain path-1 --format md
    md_res = runner.invoke(
        app,
        ["explain", "path-1", "--format", "md", "--db", str(populated_ad_db)],
    )
    assert md_res.exit_code == 0
    assert "# Active Directory Attack Path Narrative" in md_res.stdout
    assert "**Path ID**: #1" in md_res.stdout
    assert "## Step-by-Step Traversal Breakdown" in md_res.stdout
    assert "T1069.002" in md_res.stdout
    assert "Defensive Recommendations" in md_res.stdout

    # Step 4: Run arrow explain 1 --json
    json_res = runner.invoke(
        app,
        ["explain", "1", "--json", "--db", str(populated_ad_db)],
    )
    assert json_res.exit_code == 0
    data = json.loads(json_res.stdout)
    assert data["status"] == "success"
    assert data["path_id"] == 1
    assert data["hops_count"] == 4
    assert len(data["hops"]) == 4
    assert data["hops"][0]["mitre_id"] == "T1069.002"


def test_cli_explain_not_found(populated_ad_db: Path) -> None:
    """Test arrow explain with non-existent path ID."""
    res = runner.invoke(
        app,
        ["explain", "999", "--db", str(populated_ad_db)],
    )
    assert res.exit_code == 1
    assert "Saved path ID '999' not found" in res.stdout

    # JSON error output
    res_json = runner.invoke(
        app,
        ["explain", "999", "--json", "--db", str(populated_ad_db)],
    )
    assert res_json.exit_code == 1
    err_data = json.loads(res_json.stdout)
    assert err_data["status"] == "error"
    assert "999" in err_data["message"]


def test_cli_path_json_includes_path_id(populated_ad_db: Path) -> None:
    """Test arrow path --json includes the saved path_id in the JSON payload."""
    res = runner.invoke(
        app,
        ["path", "bob", "--to", "Domain Admins", "--json", "--db", str(populated_ad_db)],
    )
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["status"] == "success"
    assert "path_id" in data
    assert isinstance(data["path_id"], int)


def test_cli_explain_piped_json(populated_ad_db: Path) -> None:
    """Test piping path output directly into arrow explain via stdin '-'."""
    path_res = runner.invoke(
        app,
        ["path", "bob", "--to", "Domain Admins", "--json", "--db", str(populated_ad_db)],
    )
    assert path_res.exit_code == 0

    explain_res = runner.invoke(
        app,
        ["explain", "-", "--format", "md"],
        input=path_res.stdout,
    )
    assert explain_res.exit_code == 0
    assert "# Active Directory Attack Path Narrative" in explain_res.stdout
    assert "T1069.002" in explain_res.stdout

