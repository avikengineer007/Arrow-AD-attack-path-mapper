"""Tests for the Arrow CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from typer.testing import CliRunner

from arrow.cli import app
from arrow.graph import create_empty_graph
from arrow.sample_data import write_sample_zip

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Arrow: Active Directory Attack-Path Mapper CLI" in result.stdout
    assert "ingest" in result.stdout
    assert "graph" in result.stdout
    assert "path" in result.stdout
    assert "query" in result.stdout
    assert "blast" in result.stdout
    assert "mark" in result.stdout
    assert "list" in result.stdout


def test_cli_ingest_and_info(tmp_path: Path):
    zip_path = tmp_path / "fixture.zip"
    write_sample_zip(zip_path)
    db_path = tmp_path / "cli_test.db"

    # Ingest command
    ingest_result = runner.invoke(app, [
        "ingest",
        "--bloodhound", str(zip_path),
        "--db", str(db_path),
    ])
    assert ingest_result.exit_code == 0
    assert "Arrow Ingest Complete" in ingest_result.stdout
    assert "Ingested Nodes by Type" in ingest_result.stdout
    assert "Ingested Edges by Relationship" in ingest_result.stdout
    assert db_path.exists()

    # Graph info command
    info_result = runner.invoke(app, [
        "graph",
        "info",
        "--db", str(db_path),
    ])
    assert info_result.exit_code == 0
    assert "Active Directory Graph Overview" in info_result.stdout
    assert "Nodes by Type" in info_result.stdout
    assert "Edges by Relationship" in info_result.stdout
    assert "Top Inbound Targets" in info_result.stdout

    # Graph info with --json
    info_json = runner.invoke(app, [
        "graph",
        "info",
        "--db", str(db_path),
        "--json",
    ])
    assert info_json.exit_code == 0
    data = json.loads(info_json.stdout)
    assert data["total_nodes"] == 40
    assert data["total_edges"] == 39


def test_cli_mark_and_list_owned(tmp_path: Path):
    zip_path = tmp_path / "fixture.zip"
    write_sample_zip(zip_path)
    db_path = tmp_path / "owned_test.db"

    runner.invoke(app, ["ingest", "--bloodhound", str(zip_path), "--db", str(db_path)])

    # List initially empty
    empty_res = runner.invoke(app, ["list", "owned", "--db", str(db_path)])
    assert "No nodes are currently marked as owned" in empty_res.stdout

    # Mark owned
    mark_res = runner.invoke(app, ["mark", "owned", "victim_bob", "--db", str(db_path)])
    assert mark_res.exit_code == 0
    assert "Marked as owned: VICTIM_BOB@CORP.LOCAL" in mark_res.stdout

    # List owned
    list_res = runner.invoke(app, ["list", "owned", "--db", str(db_path)])
    assert list_res.exit_code == 0
    assert "VICTIM_BOB@CORP.LOCAL" in list_res.stdout

    # List owned --json
    list_json = runner.invoke(app, ["list", "owned", "--db", str(db_path), "--json"])
    assert list_json.exit_code == 0
    j_data = json.loads(list_json.stdout)
    assert j_data["total_owned"] == 1
    assert j_data["owned_nodes"][0]["name"] == "VICTIM_BOB@CORP.LOCAL"

    # Mark unowned
    unmark_res = runner.invoke(app, ["mark", "unowned", "victim_bob", "--db", str(db_path)])
    assert unmark_res.exit_code == 0
    assert "Unmarked owned status" in unmark_res.stdout


def test_cli_path_command(tmp_path: Path):
    zip_path = tmp_path / "fixture.zip"
    write_sample_zip(zip_path)
    db_path = tmp_path / "path_test.db"

    runner.invoke(app, ["ingest", "--bloodhound", str(zip_path), "--db", str(db_path)])

    # 1. Path with explicit start and target
    res1 = runner.invoke(app, [
        "path", "victim_bob",
        "--to", "TARGET-SRV",
        "--db", str(db_path),
    ])
    assert res1.exit_code == 0
    assert "Attack Path Chain" in res1.stdout
    assert "VICTIM_BOB@CORP.LOCAL" in res1.stdout
    assert "TARGET-SRV.CORP.LOCAL" in res1.stdout

    # 2. Path with --stealth
    res_stealth = runner.invoke(app, [
        "path", "victim_bob",
        "--to", "TARGET-SRV",
        "--stealth",
        "--db", str(db_path),
    ])
    assert res_stealth.exit_code == 0
    assert "STEALTH WEIGHTED" in res_stealth.stdout

    # 3. Path with --json
    res_json = runner.invoke(app, [
        "path", "victim_bob",
        "--to", "TARGET-SRV",
        "--db", str(db_path),
        "--json",
    ])
    assert res_json.exit_code == 0
    p_data = json.loads(res_json.stdout)
    assert p_data["status"] == "success"
    assert p_data["hops"] == 3
    assert len(p_data["segments"]) == 3

    # 4. Path with start omitted (from any owned node)
    # First mark victim_bob as owned
    runner.invoke(app, ["mark", "owned", "victim_bob", "--db", str(db_path)])
    res_omitted = runner.invoke(app, [
        "path",
        "--to", "TARGET-SRV",
        "--db", str(db_path),
    ])
    assert res_omitted.exit_code == 0
    assert "Origin: VICTIM_BOB@CORP.LOCAL" in res_omitted.stdout

    # 5. Path to "Domain Admins"
    res_da = runner.invoke(app, [
        "path", "victim_bob",
        "--to", "Domain Admins",
        "--db", str(db_path),
    ])
    assert res_da.exit_code == 0
    assert "Target: DOMAIN ADMINS@CORP.LOCAL" in res_da.stdout


def test_cli_query_command(tmp_path: Path):
    zip_path = tmp_path / "fixture.zip"
    write_sample_zip(zip_path)
    db_path = tmp_path / "query_test.db"

    runner.invoke(app, ["ingest", "--bloodhound", str(zip_path), "--db", str(db_path)])

    for qname in ["kerberoastable", "asrep", "unconstrained", "dcsync"]:
        res = runner.invoke(app, ["query", qname, "--db", str(db_path)])
        assert res.exit_code == 0
        assert f"Query Results: {qname.upper()}" in res.stdout

        # Test --json flag
        res_j = runner.invoke(app, ["query", qname, "--db", str(db_path), "--json"])
        assert res_j.exit_code == 0
        q_data = json.loads(res_j.stdout)
        assert q_data["query"] == qname
        assert q_data["count"] >= 1


def test_cli_blast_command(tmp_path: Path):
    zip_path = tmp_path / "fixture.zip"
    write_sample_zip(zip_path)
    db_path = tmp_path / "blast_test.db"

    runner.invoke(app, ["ingest", "--bloodhound", str(zip_path), "--db", str(db_path)])

    # Blast with --to-da
    res = runner.invoke(app, [
        "blast", "victim_bob",
        "--to-da",
        "--db", str(db_path),
    ])
    assert res.exit_code == 0
    assert "Blast Radius Analysis" in res.stdout
    assert "DOMAIN ADMINS REACHABLE" in res.stdout
    assert "Hop 1" in res.stdout

    # Blast with --json
    res_json = runner.invoke(app, [
        "blast", "victim_bob",
        "--db", str(db_path),
        "--json",
    ])
    assert res_json.exit_code == 0
    b_data = json.loads(res_json.stdout)
    assert b_data["total_reachable"] == 14
    assert b_data["reaches_domain_admins"] is True


def test_cli_graph_info_missing_db(tmp_path: Path):
    missing_db = tmp_path / "does_not_exist.db"
    result = runner.invoke(app, ["graph", "info", "--db", str(missing_db)])
    assert result.exit_code != 0


def test_cli_ldap_ingest_validations():
    # Neither --dc nor --bloodhound
    res1 = runner.invoke(app, ["ingest"])
    assert res1.exit_code != 0
    assert "Must specify either --dc" in res1.stdout

    # --dc without --domain
    res2 = runner.invoke(app, ["ingest", "--dc", "10.0.0.1"])
    assert res2.exit_code != 0
    assert "--domain / -d is required" in res2.stdout

    # --dc without credentials or anonymous
    res3 = runner.invoke(app, ["ingest", "--dc", "10.0.0.1", "-d", "corp.local"])
    assert res3.exit_code != 0
    assert "Username" in res3.stdout or "Credentials" in res3.stdout

    # Unreachable DC with --json
    res4 = runner.invoke(app, [
        "ingest",
        "--dc", "127.0.0.1",
        "-d", "corp.local",
        "--anonymous",
        "--json",
    ])
    assert res4.exit_code != 0
    j_err = json.loads(res4.stdout)
    assert j_err["status"] == "error"
    assert j_err["type"] == "connection_error"


def test_cli_password_fallback_mechanisms():
    from unittest.mock import patch
    import os

    # 1. Password from ARROW_DC_PASSWORD env var
    with patch.dict(os.environ, {"ARROW_DC_PASSWORD": "env_secret_password"}), \
         patch("arrow.cli.LDAPCollector") as mock_collector_cls:
        mock_instance = mock_collector_cls.return_value
        mock_instance.warnings = []
        mock_instance.collect_all.return_value = create_empty_graph()

        runner.invoke(app, [
            "ingest",
            "--dc", "10.0.0.1",
            "-d", "corp.local",
            "-u", "jsmith",
            "--json",
        ])
        assert mock_collector_cls.call_args[0][0].password == "env_secret_password"
    
    # 2. Interactive getpass prompt when -p is omitted
    with patch.dict(os.environ, {}, clear=True), \
         patch("getpass.getpass", return_value="prompted_password") as mock_getpass, \
         patch("arrow.cli.LDAPCollector") as mock_collector_cls:
        mock_instance = mock_collector_cls.return_value
        mock_instance.warnings = []
        mock_instance.collect_all.return_value = create_empty_graph()

        runner.invoke(app, [
            "ingest",
            "--dc", "10.0.0.1",
            "-d", "corp.local",
            "-u", "jsmith",
        ])
        assert mock_getpass.called
        assert mock_collector_cls.call_args[0][0].password == "prompted_password"

    # 3. JSON mode without password prompts user to set ARROW_DC_PASSWORD
    with patch.dict(os.environ, {}, clear=True):
        res_json = runner.invoke(app, [
            "ingest",
            "--dc", "10.0.0.1",
            "-d", "corp.local",
            "-u", "jsmith",
            "--json",
        ])
        assert res_json.exit_code != 0
        j_data = json.loads(res_json.stdout)
        assert "ARROW_DC_PASSWORD" in j_data["message"]



