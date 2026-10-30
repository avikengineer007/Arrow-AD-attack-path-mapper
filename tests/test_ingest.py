"""Tests for BloodHound ingestion and relationship mapping."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import networkx as nx
import pytest

from arrow.ingest.bloodhound import BloodHoundImporter
from arrow.sample_data import build_synthetic_dataset, write_sample_zip


@pytest.fixture
def minimal_fake_json_dir(tmp_path: Path) -> Path:
    """Create minimal fake SharpHound JSON files representing all AD object types."""
    export_dir = tmp_path / "bloodhound_export"
    export_dir.mkdir()

    users_data = {
        "data": [
            {
                "ObjectIdentifier": "S-USER-1",
                "Properties": {"name": "ATTACKER@TEST.LOCAL", "enabled": True},
                "Aces": [],
                "AllowedToDelegate": [{"ObjectIdentifier": "S-COMP-1"}],
            },
            {
                "ObjectIdentifier": "S-USER-2",
                "Properties": {"name": "TARGET_USER@TEST.LOCAL"},
                "Aces": [
                    {
                        "PrincipalSID": "S-GROUP-1",
                        "RightName": "ForceChangePassword",
                        "IsInherited": False,
                    }
                ],
            },
        ],
        "meta": {"type": "users", "count": 2, "version": 5},
    }

    groups_data = {
        "data": [
            {
                "ObjectIdentifier": "S-GROUP-1",
                "Properties": {"name": "OPERATORS@TEST.LOCAL"},
                "Members": [{"ObjectIdentifier": "S-USER-1", "ObjectType": "User"}],
                "Aces": [
                    {
                        "PrincipalSID": "S-USER-1",
                        "RightName": "AddMember",
                        "IsInherited": False,
                    }
                ],
            }
        ],
        "meta": {"type": "groups", "count": 1, "version": 5},
    }

    computers_data = {
        "data": [
            {
                "ObjectIdentifier": "S-COMP-1",
                "Properties": {"name": "SRV01.TEST.LOCAL"},
                "LocalAdmins": {"Results": [{"ObjectIdentifier": "S-GROUP-1"}]},
                "RemoteDesktop": {"Results": [{"ObjectIdentifier": "S-USER-1"}]},
                "SQLAdmin": {"Results": [{"ObjectIdentifier": "S-USER-1"}]},
                "AllowedToAct": {"Results": [{"ObjectIdentifier": "S-USER-2"}]},
                "Sessions": {"Results": [{"UserId": "S-USER-2", "ComputerId": "S-COMP-1"}]},
                "Aces": [
                    {
                        "PrincipalSID": "S-GROUP-1",
                        "RightName": "GenericAll",
                        "IsInherited": False,
                    },
                    {
                        "PrincipalSID": "S-USER-1",
                        "RightName": "WriteDacl",
                        "IsInherited": False,
                    },
                    {
                        "PrincipalSID": "S-USER-1",
                        "RightName": "WriteOwner",
                        "IsInherited": False,
                    },
                ],
            }
        ],
        "meta": {"type": "computers", "count": 1, "version": 5},
    }

    domains_data = {
        "data": [
            {
                "ObjectIdentifier": "S-DOMAIN-1",
                "Properties": {"name": "TEST.LOCAL"},
                "Aces": [
                    {
                        "PrincipalSID": "S-GROUP-1",
                        "RightName": "DCSync",
                        "IsInherited": False,
                    }
                ],
            }
        ],
        "meta": {"type": "domains", "count": 1, "version": 5},
    }

    ous_data = {
        "data": [
            {
                "ObjectIdentifier": "S-OU-1",
                "Properties": {"name": "SERVERS_OU"},
                "Aces": [
                    {
                        "PrincipalSID": "S-USER-1",
                        "RightName": "GenericWrite",
                        "IsInherited": False,
                    }
                ],
            }
        ],
        "meta": {"type": "ous", "count": 1, "version": 5},
    }

    gpos_data = {
        "data": [
            {
                "ObjectIdentifier": "S-GPO-1",
                "Properties": {"name": "DEFAULT POLICY"},
                "Aces": [
                    {
                        "PrincipalSID": "S-USER-1",
                        "RightName": "Owns",
                        "IsInherited": False,
                    }
                ],
            }
        ],
        "meta": {"type": "gpos", "count": 1, "version": 5},
    }

    for name, data in [
        ("users.json", users_data),
        ("groups.json", groups_data),
        ("computers.json", computers_data),
        ("domains.json", domains_data),
        ("ous.json", ous_data),
        ("gpos.json", gpos_data),
    ]:
        with open(export_dir / name, "w", encoding="utf-8") as f:
            json.dump(data, f)

    return export_dir


def test_minimal_fake_json_ingest(minimal_fake_json_dir: Path):
    importer = BloodHoundImporter()
    graph = importer.import_path(minimal_fake_json_dir)

    # Verify Nodes
    assert graph.has_node("S-USER-1")
    assert graph.nodes["S-USER-1"]["type"] == "User"
    assert graph.nodes["S-USER-1"]["name"] == "ATTACKER@TEST.LOCAL"

    assert graph.has_node("S-GROUP-1")
    assert graph.nodes["S-GROUP-1"]["type"] == "Group"

    assert graph.has_node("S-COMP-1")
    assert graph.nodes["S-COMP-1"]["type"] == "Computer"

    assert graph.has_node("S-DOMAIN-1")
    assert graph.nodes["S-DOMAIN-1"]["type"] == "Domain"

    assert graph.has_node("S-OU-1")
    assert graph.nodes["S-OU-1"]["type"] == "OU"

    assert graph.has_node("S-GPO-1")
    assert graph.nodes["S-GPO-1"]["type"] == "GPO"

    # Verify Edges
    # MemberOf
    assert graph.has_edge("S-USER-1", "S-GROUP-1", key="MemberOf")
    # AddMember
    assert graph.has_edge("S-USER-1", "S-GROUP-1", key="AddMember")
    # AdminTo
    assert graph.has_edge("S-GROUP-1", "S-COMP-1", key="AdminTo")
    # CanRDP
    assert graph.has_edge("S-USER-1", "S-COMP-1", key="CanRDP")
    # SQLAdmin
    assert graph.has_edge("S-USER-1", "S-COMP-1", key="SQLAdmin")
    # AllowedToAct
    assert graph.has_edge("S-USER-2", "S-COMP-1", key="AllowedToAct")
    # AllowedToDelegate
    assert graph.has_edge("S-USER-1", "S-COMP-1", key="AllowedToDelegate")
    # HasSession (Computer -> User)
    assert graph.has_edge("S-COMP-1", "S-USER-2", key="HasSession")
    # GenericAll
    assert graph.has_edge("S-GROUP-1", "S-COMP-1", key="GenericAll")
    # WriteDacl
    assert graph.has_edge("S-USER-1", "S-COMP-1", key="WriteDacl")
    # WriteOwner
    assert graph.has_edge("S-USER-1", "S-COMP-1", key="WriteOwner")
    # ForceChangePassword
    assert graph.has_edge("S-GROUP-1", "S-USER-2", key="ForceChangePassword")
    # GenericWrite
    assert graph.has_edge("S-USER-1", "S-OU-1", key="GenericWrite")
    # Owns
    assert graph.has_edge("S-USER-1", "S-GPO-1", key="Owns")
    # DCSync
    assert graph.has_edge("S-GROUP-1", "S-DOMAIN-1", key="DCSync")


def test_zip_archive_ingest(minimal_fake_json_dir: Path, tmp_path: Path):
    zip_file = tmp_path / "bloodhound_test.zip"
    with zipfile.ZipFile(zip_file, "w") as zf:
        for json_path in minimal_fake_json_dir.glob("*.json"):
            zf.write(json_path, arcname=json_path.name)

    importer = BloodHoundImporter()
    graph = importer.import_path(zip_file)
    assert graph.number_of_nodes() == 7
    assert graph.number_of_edges() == 15


def test_synthetic_fixture_and_planted_path(tmp_path: Path):
    zip_dest = tmp_path / "sample_dataset.zip"
    write_sample_zip(zip_dest)
    assert zip_dest.exists()

    importer = BloodHoundImporter()
    graph = importer.import_path(zip_dest)

    # Verify counts: ~20 users, 5 groups, 10 computers
    users = [n for n, d in graph.nodes(data=True) if d.get("type") == "User"]
    groups = [n for n, d in graph.nodes(data=True) if d.get("type") == "Group"]
    computers = [n for n, d in graph.nodes(data=True) if d.get("type") == "Computer"]

    assert len(users) == 20
    assert len(groups) == 5
    assert len(computers) == 10

    # Planted attack path verification:
    # user (victim_bob) -> group (Help Desk) -> GenericAll -> computer (PIVOT-SRV) -> AdminTo -> another computer (TARGET-SRV)
    bob_sid = "S-1-5-21-1111111111-2222222222-3333333333-1202"
    help_desk_sid = "S-1-5-21-1111111111-2222222222-3333333333-1102"
    pivot_sid = "S-1-5-21-1111111111-2222222222-3333333333-2005"
    target_sid = "S-1-5-21-1111111111-2222222222-3333333333-2006"

    assert graph.has_edge(bob_sid, help_desk_sid, key="MemberOf")
    assert graph.has_edge(help_desk_sid, pivot_sid, key="GenericAll")
    assert graph.has_edge(pivot_sid, target_sid, key="AdminTo")

    # Shortest path traversal
    path = nx.shortest_path(graph, bob_sid, target_sid)
    assert path == [bob_sid, help_desk_sid, pivot_sid, target_sid]


def test_zip_bomb_file_size_ceiling_protection(tmp_path: Path):
    """Verify that archives with files exceeding the safety ceiling are skipped safely."""
    zip_path = tmp_path / "oversized.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("users.json", json.dumps({"data": [], "meta": {"type": "users"}}))

    importer = BloodHoundImporter()
    # Temporarily set ceiling lower for test
    from unittest.mock import patch
    with patch("arrow.ingest.bloodhound.MAX_UNCOMPRESSED_FILE_BYTES", 5):
        importer.import_path(zip_path)

    assert any("exceeds safety ceiling" in w for w in importer.warnings)
    assert "users.json" not in importer.ingested_files


def test_zip_bomb_streaming_decompression_guard(tmp_path: Path):
    """Verify that streaming read halts if decompressed bytes exceed ceiling mid-stream."""
    zip_path = tmp_path / "forged_header.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("users.json", b"A" * 10)

    importer = BloodHoundImporter()
    from unittest.mock import patch
    import io

    # Mock open stream returning bytes that exceed ceiling
    fake_stream = io.BytesIO(b"A" * 500)
    with patch("arrow.ingest.bloodhound.MAX_UNCOMPRESSED_FILE_BYTES", 100), \
         patch("zipfile.ZipFile.open", return_value=fake_stream):
        importer.import_path(zip_path)

    assert any("exceeded size limit" in w for w in importer.warnings)


def test_decompression_memory_error_degradation(tmp_path: Path):
    """Verify that a MemoryError degrades gracefully rather than crashing."""
    zip_path = tmp_path / "oom.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("users.json", json.dumps({"data": []}))

    importer = BloodHoundImporter()
    from unittest.mock import patch
    with patch("zipfile.ZipFile.open", side_effect=MemoryError("Simulated system OOM")):
        importer.import_path(zip_path)

    assert any("Failed to parse" in w or "Memory limit reached" in w for w in importer.warnings)

