"""
Tests for optional stretch features: LLM-assisted narration and ADCS attack path mapping (ESC1, ESC4, ESC8).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from arrow.cli import app
from arrow.db import load_graph, save_graph
from arrow.explain import explain_path, explain_path_llm
from arrow.ingest.bloodhound import BloodHoundImporter
from arrow.queries import find_path, run_named_query
from arrow.sample_data import write_sample_adcs_zip

runner = CliRunner()


@pytest.fixture
def adcs_db(tmp_path: Path) -> Path:
    """Ingest synthetic dataset containing ADCS PKI objects (ESC1, ESC4, ESC8)."""
    zip_path = tmp_path / "adcs_fixture.zip"
    write_sample_adcs_zip(zip_path)

    db_path = tmp_path / "adcs_test.db"
    importer = BloodHoundImporter()
    graph = importer.import_path(zip_path)
    save_graph(graph, db_path=db_path)
    return db_path


def test_llm_explain_fallback_without_api_key() -> None:
    """Verify explain_path_llm falls back gracefully when ANTHROPIC_API_KEY is not set."""
    with patch.dict(os.environ, {}, clear=True):
        res = explain_path_llm({"chain": "A ──[MemberOf]──> B"})
        assert res is None


def test_llm_explain_with_mocked_anthropic() -> None:
    """Verify explain_path_llm constructs prompt and calls Anthropic API properly."""
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_block = MagicMock()
    mock_block.text = (
        "As a senior red teamer, the adversary initiates lateral movement from alice to the target server. "
        "Leveraging local administrator access via SMB (T1021.002), we execute remote code and pivot to compromise Domain Admins."
    )
    mock_response.content = [mock_block]
    mock_client.messages.create.return_value = mock_response

    with patch("anthropic.Anthropic", return_value=mock_client):
        sample_path = {
            "start": {"name": "alice", "type": "User"},
            "target": {"name": "Domain Admins", "type": "Group"},
            "hops": 1,
            "chain": "alice ──[AdminTo]──> Domain Admins",
            "segments": [
                {
                    "step": 1,
                    "source": {"name": "alice", "type": "User"},
                    "edge_type": "AdminTo",
                    "target": {"name": "Domain Admins", "type": "Group"},
                    "weight": 5.0,
                }
            ],
        }
        res = explain_path_llm(sample_path, api_key="sk-ant-test-key-12345")
        assert res is not None
        assert "T1021.002" in res
        assert "senior red teamer" in res
        assert mock_client.messages.create.called

        # Verify system prompt instructs not to hallucinate
        kwargs = mock_client.messages.create.call_args[1]
        assert "DO NOT invent, hallucinate" in kwargs["system"]
        assert "claude-sonnet-4-6" in kwargs["model"]


def test_cli_explain_llm_flag_fallback(adcs_db: Path) -> None:
    """Test arrow explain --llm flag falls back to template and outputs notice when no key is set."""
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}):
        res = runner.invoke(app, [
            "explain", "victim_bob ──[MemberOf]──> HelpDesk ──[AdminTo]──> DC01",
            "--llm",
            "--db", str(adcs_db),
        ])
        assert res.exit_code == 0
        assert "Notice: ANTHROPIC_API_KEY is not configured" in res.stdout
        assert "Active Directory Attack Path Narrative Explanation" in res.stdout
        assert "T1069.002" in res.stdout


def test_adcs_queries(adcs_db: Path) -> None:
    """Test named queries for ESC1, ESC4, and ESC8 on ingested ADCS dataset."""
    graph = load_graph(adcs_db)

    # ESC1 Query
    esc1_res = run_named_query(graph, "esc1")
    assert len(esc1_res) >= 1
    found_esc1 = any("ESC1-USER-CERT" in r["name"] for r in esc1_res)
    assert found_esc1
    item = next(r for r in esc1_res if "ESC1-USER-CERT" in r["name"])
    assert item["enrollee_supplies_san"] is True
    assert item["client_auth"] is True

    # ESC4 Query
    esc4_res = run_named_query(graph, "esc4")
    assert len(esc4_res) >= 1
    found_esc4 = any("ESC4-WEB-CERT" in r["name"] for r in esc4_res)
    assert found_esc4
    item4 = next(r for r in esc4_res if "ESC4-WEB-CERT" in r["name"])
    assert "HELP DESK" in item4["principal"].upper()

    # ESC8 Query
    esc8_res = run_named_query(graph, "esc8")
    assert len(esc8_res) >= 1
    found_esc8 = any("CORP-CA01" in r["name"] for r in esc8_res)
    assert found_esc8
    item8 = next(r for r in esc8_res if "CORP-CA01" in r["name"])
    assert "certsrv" in item8["endpoint"].lower()

    # Aggregated ADCS Query
    adcs_all = run_named_query(graph, "adcs")
    assert len(adcs_all) >= 3


def test_cli_query_adcs_commands(adcs_db: Path) -> None:
    """Test arrow query esc1, esc4, esc8, and adcs CLI table outputs."""
    # arrow query esc1
    res1 = runner.invoke(app, ["query", "esc1", "--db", str(adcs_db)])
    assert res1.exit_code == 0
    assert "ESC1-USER-CERT" in res1.stdout
    assert "ESC1" in res1.stdout

    # arrow query esc4
    res4 = runner.invoke(app, ["query", "esc4", "--db", str(adcs_db)])
    assert res4.exit_code == 0
    assert "ESC4-WEB-CERT" in res4.stdout

    # arrow query esc8
    res8 = runner.invoke(app, ["query", "esc8", "--db", str(adcs_db)])
    assert res8.exit_code == 0
    assert "CORP-CA01" in res8.stdout
    assert "ESC8" in res8.stdout

    # arrow query adcs --json
    res_json = runner.invoke(app, ["query", "adcs", "--json", "--db", str(adcs_db)])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data["count"] >= 3
    assert any("ESC1" in str(r.get("vulnerability")) for r in data["results"])


def test_adcs_attack_path_escalation(adcs_db: Path) -> None:
    """Verify that an ESC1 certificate template creates an attack path to Domain Admins."""
    graph = load_graph(adcs_db)

    # Path from All Employees (which has ADCSEnroll on ESC1 template) to Domain Admins
    path_res = find_path(graph, start="All Employees", target="Domain Admins", stealth=True)
    assert path_res.hops >= 1
    assert "ESC1-USER-CERT" in path_res.chain or "Domain Admins" in path_res.chain

    # Explain the ADCS path
    explained = explain_path(path_res)
    assert explained.hops_count >= 1
    # Check that ADCSEnroll or GenericAll has valid MITRE ID
    has_mitre = any(h.mitre_id in ("T1649", "T1222.001", "T1098") for h in explained.hops)
    assert has_mitre
