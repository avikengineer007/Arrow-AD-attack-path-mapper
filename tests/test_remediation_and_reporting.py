"""
Tests for Arrow remediation analysis, export (DOT/Mermaid), reporting (MD/HTML), and demo commands.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from typer.testing import CliRunner

from arrow.cli import app
from arrow.db import save_graph
from arrow.export import export_to_dot, export_to_mermaid, extract_key_paths_subgraph
from arrow.graph import create_empty_graph
from arrow.remediation import compute_remediation_plan, generate_remediation_advice
from arrow.report import generate_html_report, generate_markdown_report

runner = CliRunner()


@pytest.fixture
def multi_path_db(tmp_path: Path) -> Path:
    """
    Create a test database with multiple converging attack paths to Domain Admins:
    Path 1: attacker_1 -> MemberOf -> HelpDesk -> GenericAll -> DA_Group
    Path 2: attacker_2 -> AdminTo -> WS01 -> HasSession -> DA_User -> MemberOf -> DA_Group
    """
    db_file = tmp_path / "multi_path.db"
    g = create_empty_graph()

    # Nodes
    g.add_node("U-ATT1", objectid="U-ATT1", type="User", name="attacker_1", properties={"owned": True})
    g.add_node("U-ATT2", objectid="U-ATT2", type="User", name="attacker_2", properties={"owned": True})
    g.add_node("G-HD", objectid="G-HD", type="Group", name="HelpDesk", properties={})
    g.add_node("C-WS01", objectid="C-WS01", type="Computer", name="WS01.CORP.LOCAL", properties={})
    g.add_node("U-DA", objectid="U-DA", type="User", name="da_user", properties={})
    g.add_node("G-DA", objectid="G-DA", type="Group", name="Domain Admins", properties={})

    # Edges for Path 1
    g.add_edge("U-ATT1", "G-HD", key="MemberOf", edge_type="MemberOf")
    g.add_edge("G-HD", "G-DA", key="GenericAll", edge_type="GenericAll")

    # Edges for Path 2
    g.add_edge("U-ATT2", "C-WS01", key="AdminTo", edge_type="AdminTo")
    g.add_edge("C-WS01", "U-DA", key="HasSession", edge_type="HasSession")
    g.add_edge("U-DA", "G-DA", key="MemberOf", edge_type="MemberOf")

    save_graph(g, db_file)
    return db_file


def test_remediation_advice_generation() -> None:
    """Test plain-language remediation text generation for various edge types."""
    advice_memberof = generate_remediation_advice("bob@CORP.LOCAL", "User", "MemberOf", "Admins", "Group")
    assert "Remove 'bob' from group 'Admins'" in advice_memberof

    advice_genericall = generate_remediation_advice("HelpDesk", "Group", "GenericAll", "SRV01", "Computer")
    assert "Remove GenericAll Access Control Entry" in advice_genericall

    advice_session = generate_remediation_advice("SRV01", "Computer", "HasSession", "Alice", "User")
    assert "Terminate active/disconnected session of 'Alice'" in advice_session

    advice_rbcd = generate_remediation_advice("Bob", "User", "AllowedToAct", "DC01", "Computer")
    assert "msDS-AllowedToActOnBehalfOfOtherIdentity" in advice_rbcd


def test_compute_remediation_plan(multi_path_db: Path) -> None:
    """Test min-cut / greedy maximum path elimination across multiple attack paths."""
    from arrow.db import load_graph

    graph = load_graph(multi_path_db)
    plan = compute_remediation_plan(graph, target="Domain Admins")

    assert plan.target["name"] == "Domain Admins"
    assert plan.total_paths_identified == 2
    assert len(plan.items) >= 2
    assert plan.paths_remaining == 0

    # Ensure paths eliminated metrics are computed
    for item in plan.items:
        assert item.paths_eliminated > 0
        assert item.paths_eliminated_pct > 0
        assert len(item.remediation) > 10

    d = plan.to_dict()
    assert d["total_paths_identified"] == 2
    assert len(d["recommendations"]) >= 2


def test_export_dot_and_mermaid(multi_path_db: Path) -> None:
    """Test exporting graph to Graphviz DOT and Mermaid formats."""
    from arrow.db import load_graph

    graph = load_graph(multi_path_db)
    sub = extract_key_paths_subgraph(graph, target="Domain Admins")

    dot_str = export_to_dot(sub)
    assert 'digraph "' in dot_str
    assert "node_" in dot_str
    assert "Domain Admins" in dot_str or "G_DA" in dot_str

    mermaid_str = export_to_mermaid(sub)
    assert "flowchart LR" in mermaid_str
    assert "classDef" in mermaid_str
    assert "-->|" in mermaid_str


def test_report_generation_markdown_and_html(multi_path_db: Path) -> None:
    """Test generating comprehensive findings reports in Markdown and self-contained HTML."""
    from arrow.db import load_graph

    graph = load_graph(multi_path_db)

    # Markdown Report
    md = generate_markdown_report(graph, target="Domain Admins")
    assert "# 🏹 Arrow Active Directory Security Assessment Report" in md
    assert "Executive Summary" in md
    assert "Remediation Plan" in md
    assert "```mermaid" in md

    # Self-Contained HTML Report
    html_out = generate_html_report(graph, target="Domain Admins")
    assert "<!DOCTYPE html>" in html_out
    assert "<style>" in html_out
    assert "Arrow Security Report" in html_out
    assert "Remediation Plan" in html_out
    # Assert self-contained: no external CDN scripts or stylesheet links
    assert "http://" not in html_out and "https://" not in html_out


def test_cli_fix_command(multi_path_db: Path) -> None:
    """Test arrow fix CLI command (table output and JSON mode)."""
    # Table mode
    res = runner.invoke(app, ["fix", "--target", "Domain Admins", "--db", str(multi_path_db)])
    assert res.exit_code == 0
    assert "Arrow Remediation Analysis" in res.stdout
    assert "Recommended Edge Remediations" in res.stdout
    assert "Impact" in res.stdout

    # JSON mode
    res_json = runner.invoke(app, ["fix", "--target", "Domain Admins", "--json", "--db", str(multi_path_db)])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data["status"] == "success"
    assert data["total_paths_identified"] == 2
    assert len(data["recommendations"]) >= 2


def test_cli_export_command(multi_path_db: Path, tmp_path: Path) -> None:
    """Test arrow export CLI command for DOT and Mermaid."""
    out_dot = tmp_path / "test.dot"
    res_dot = runner.invoke(app, ["export", "--format", "dot", "-o", str(out_dot), "--db", str(multi_path_db)])
    assert res_dot.exit_code == 0
    assert out_dot.exists()
    assert "digraph" in out_dot.read_text(encoding="utf-8")

    out_mmd = tmp_path / "test.mermaid"
    res_mmd = runner.invoke(app, ["export", "--format", "mermaid", "-o", str(out_mmd), "--db", str(multi_path_db)])
    assert res_mmd.exit_code == 0
    assert out_mmd.exists()
    assert "flowchart LR" in out_mmd.read_text(encoding="utf-8")


def test_cli_report_command(multi_path_db: Path, tmp_path: Path) -> None:
    """Test arrow report CLI command generating MD and HTML report files."""
    rep_md = tmp_path / "report.md"
    res_md = runner.invoke(app, ["report", "--format", "md", "-o", str(rep_md), "--db", str(multi_path_db)])
    assert res_md.exit_code == 0
    assert rep_md.exists()
    assert "Arrow Active Directory Security Assessment Report" in rep_md.read_text(encoding="utf-8")

    rep_html = tmp_path / "report.html"
    res_html = runner.invoke(app, ["report", "--format", "html", "-o", str(rep_html), "--db", str(multi_path_db)])
    assert res_html.exit_code == 0
    assert rep_html.exists()
    assert "<!DOCTYPE html>" in rep_html.read_text(encoding="utf-8")


def test_cli_demo_command(tmp_path: Path) -> None:
    """Test arrow demo automated end-to-end execution."""
    demo_dir = tmp_path / "demo_run"
    res = runner.invoke(app, ["demo", "--output-dir", str(demo_dir)])
    assert res.exit_code == 0
    assert "Arrow: Automated End-to-End Active Directory Demonstration" in res.stdout
    assert "1. Ingestion Complete:" in res.stdout
    assert "2. Attack Path Found:" in res.stdout
    assert "3. Narrative Explained:" in res.stdout
    assert "4. Key Remediation (Min-Cut):" in res.stdout
    assert "5. Reports Exported:" in res.stdout

    # Verify generated artifacts
    assert (demo_dir / "arrow_demo.db").exists()
    assert (demo_dir / "arrow_demo_report.html").exists()
    assert (demo_dir / "arrow_demo_report.md").exists()
    assert (demo_dir / "arrow_demo_graph.mermaid").exists()
    assert (demo_dir / "arrow_demo_graph.dot").exists()

    # Test demo JSON mode
    demo_dir_json = tmp_path / "demo_run_json"
    res_json = runner.invoke(app, ["demo", "--json", "--output-dir", str(demo_dir_json)])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data["status"] == "success"
    assert "attack_path" in data
    assert "explanation" in data
    assert "remediation" in data
    assert "generated_reports" in data


def test_dot_and_mermaid_escaping_security() -> None:
    """Verify that quotes, backslashes, and brackets in node names are safely escaped."""
    from arrow.graph import add_ad_edge, add_ad_node, create_empty_graph
    from arrow.export import export_to_dot, export_to_mermaid

    g = create_empty_graph()
    evil_name = 'User" ] ; evil_node [ label="PWNED\\Hack'
    evil_edge = 'GenericAll" ; evil_edge'

    add_ad_node(g, "S-EVIL-1", node_type="User", name=evil_name)
    add_ad_node(g, "S-TARGET-1", node_type="Domain", name="CORP.LOCAL")
    add_ad_edge(g, "S-EVIL-1", "S-TARGET-1", edge_type=evil_edge)

    dot_str = export_to_dot(g)
    # Quotes in labels must be escaped as \"
    assert r'User\" ] ; evil_node [ label=\"PWNED\\Hack' in dot_str
    assert r'GenericAll\" ; evil_edge' in dot_str

    mmd_str = export_to_mermaid(g)
    # Quotes must be converted to single quotes, brackets to parentheses
    assert "User' ) ; evil_node ( label='PWNED\\Hack" in mmd_str

