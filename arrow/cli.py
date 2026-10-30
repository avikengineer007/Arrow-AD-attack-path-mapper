"""Arrow CLI - Active Directory Attack-Path Mapper."""

from __future__ import annotations

import getpass
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from arrow.db import get_saved_path, load_graph, save_computed_path, save_graph
from arrow.explain import explain_path, explain_path_llm
from arrow.export import export_to_dot, export_to_mermaid, extract_key_paths_subgraph
from arrow.graph import compute_graph_stats
from arrow.ingest.bloodhound import BloodHoundImporter
from arrow.ingest.ldap import LDAPCollector, LDAPIngestionConfig
from arrow.queries import (
    AVAILABLE_QUERIES,
    compute_blast_radius,
    find_path,
    list_owned_nodes,
    mark_node_owned,
    run_named_query,
)
from arrow.remediation import compute_remediation_plan
from arrow.report import generate_html_report, generate_markdown_report
from arrow.sample_data import write_sample_zip

# Ensure UTF-8 output when possible on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

app = typer.Typer(
    name="arrow",
    help="Arrow: Active Directory Attack-Path Mapper CLI",
    add_completion=False,
)
console = Console(highlight=False)

DEFAULT_DB_PATH = Path("./arrow.db")


# ----------------------------------------------------------------------
# arrow ingest
# ----------------------------------------------------------------------
@app.command(name="ingest")
def ingest(
    # Live LDAP options
    dc: str | None = typer.Option(
        None,
        "--dc",
        help="IP address or hostname of Domain Controller for direct live LDAP collection.",
    ),
    domain: str | None = typer.Option(
        None,
        "-d",
        "--domain",
        help="Active Directory domain name (e.g. corp.local). Required with --dc.",
    ),
    user: str | None = typer.Option(
        None,
        "-u",
        "--user",
        help="Domain username (e.g. 'john' or 'john@corp.local'). Optional if --anonymous.",
    ),
    password: str | None = typer.Option(
        None,
        "-p",
        "--password",
        help="Domain user password. (Note: using ARROW_DC_PASSWORD or interactive masked prompt is recommended to avoid shell history exposure).",
    ),
    ldaps: bool = typer.Option(
        False,
        "--ldaps",
        help="Use LDAPS (SSL over port 636) instead of plain LDAP (port 389).",
    ),
    anonymous: bool = typer.Option(
        False,
        "--anonymous",
        help="Perform anonymous LDAP bind testing without credentials.",
    ),
    local_admin: bool = typer.Option(
        False,
        "--local-admin",
        help="Query computers via SMB/SAMR & NetSessionEnum for AdminTo and HasSession edges (requires admin rights per host).",
    ),
    # BloodHound offline export option
    bloodhound: Path | None = typer.Option(
        None,
        "--bloodhound",
        "-b",
        help="Path to SharpHound/BloodHound .zip archive or directory of JSON files.",
        exists=True,
        file_okay=True,
        dir_okay=True,
        readable=True,
    ),
    # Common options
    db: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        help="Path to SQLite output database (default: ./arrow.db).",
    ),
    overwrite: bool = typer.Option(
        True,
        "--overwrite/--append",
        help="Overwrite existing database tables or append into them.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output summary results as JSON.",
    ),
) -> None:
    """Ingest Active Directory data into SQLite via direct live LDAP or offline BloodHound export."""
    # Validation
    if not dc and not bloodhound:
        err_msg = "Must specify either --dc <ip_or_hostname> for live collection, or --bloodhound <path.zip> for offline export."
        if json_output:
            print(json.dumps({"status": "error", "message": err_msg}))
        else:
            console.print(f"[bold red]Ingest error:[/bold red] {err_msg}")
        raise typer.Exit(code=1)

    if dc and not domain:
        err_msg = "--domain / -d is required when specifying --dc for live LDAP collection."
        if json_output:
            print(json.dumps({"status": "error", "message": err_msg}))
        else:
            console.print(f"[bold red]Ingest error:[/bold red] {err_msg}")
        raise typer.Exit(code=1)

    if dc and not anonymous:
        if not user:
            err_msg = "Username (-u / --user) is required for live LDAP unless using --anonymous."
            if json_output:
                print(json.dumps({"status": "error", "message": err_msg}))
            else:
                console.print(f"[bold red]Ingest error:[/bold red] {err_msg}")
            raise typer.Exit(code=1)

        # Secure password resolution: -p -> ARROW_DC_PASSWORD env var -> getpass interactive prompt
        if password is None:
            password = os.environ.get("ARROW_DC_PASSWORD")
            if password is None:
                if json_output:
                    err_msg = "Password (-p / --password or ARROW_DC_PASSWORD environment variable) is required in JSON mode."
                    print(json.dumps({"status": "error", "message": err_msg}))
                    raise typer.Exit(code=1)
                try:
                    password = getpass.getpass(f"Enter password for {user}: ")
                except (KeyboardInterrupt, EOFError):
                    console.print("\n[yellow]Ingest cancelled by user.[/yellow]")
                    raise typer.Exit(code=1)

        if password is None or not password.strip():
            err_msg = "A non-empty password is required for authenticated LDAP collection."
            if json_output:
                print(json.dumps({"status": "error", "message": err_msg}))
            else:
                console.print(f"[bold red]Ingest error:[/bold red] {err_msg}")
            raise typer.Exit(code=1)

    start_time = time.perf_counter()
    warnings: list[str] = []
    source_desc = f"LDAP DC {dc} ({domain})" if dc else f"BloodHound archive {bloodhound}"

    if not json_output:
        status_ctx = console.status(f"[bold cyan]Ingesting Active Directory data from {source_desc}...[/bold cyan]")
        status_ctx.start()
    else:
        status_ctx = None

    try:
        if dc:
            cfg = LDAPIngestionConfig(
                dc=dc,
                domain=domain,
                user=user,
                password=password,
                ldaps=ldaps,
                anonymous=anonymous,
                local_admin=local_admin,
            )
            collector = LDAPCollector(cfg)
            graph = collector.collect_all()
            warnings = collector.warnings
        else:
            importer = BloodHoundImporter()
            graph = importer.import_path(bloodhound)  # type: ignore[arg-type]
            warnings = importer.warnings

        save_graph(graph, db_path=db, overwrite=overwrite)

    except PermissionError as perm_err:
        if status_ctx:
            status_ctx.stop()
        if json_output:
            print(json.dumps({"status": "error", "type": "auth_failure", "message": str(perm_err)}))
        else:
            console.print(f"[bold red]Authentication Error:[/bold red] {perm_err}")
        raise typer.Exit(code=1)

    except ConnectionError as conn_err:
        if status_ctx:
            status_ctx.stop()
        if json_output:
            print(json.dumps({"status": "error", "type": "connection_error", "message": str(conn_err)}))
        else:
            console.print(f"[bold red]Connection Error:[/bold red] {conn_err}")
        raise typer.Exit(code=1)

    except Exception as exc:
        if status_ctx:
            status_ctx.stop()
        if json_output:
            print(json.dumps({"status": "error", "message": str(exc)}))
        else:
            console.print(f"[bold red]Ingest error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if status_ctx:
        status_ctx.stop()

    elapsed = time.perf_counter() - start_time
    stats = compute_graph_stats(graph)

    if json_output:
        payload = {
            "status": "success",
            "source": source_desc,
            "database": str(db.resolve()),
            "elapsed_seconds": round(elapsed, 3),
            "total_nodes": stats["total_nodes"],
            "total_edges": stats["total_edges"],
            "nodes_by_type": stats["nodes_by_type"],
            "edges_by_type": stats["edges_by_type"],
            "warnings": warnings,
        }
        print(json.dumps(payload, indent=2))
        return

    # Rich summary
    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]Arrow Ingest Complete[/bold cyan]\n"
            f"[dim]Source:[/dim] [white]{source_desc}[/white]\n"
            f"[dim]Database:[/dim] [green]{db.resolve()}[/green] | "
            f"[dim]Elapsed Time:[/dim] [yellow]{elapsed:.2f}s[/yellow]",
            title="[ Ingest Summary ]",
            border_style="cyan",
            box=box.ROUNDED,
            safe_box=True,
        )
    )

    node_table = Table(title="Ingested Nodes by Type", box=box.ROUNDED, safe_box=True, header_style="bold magenta")
    node_table.add_column("Node Type", style="bold")
    node_table.add_column("Count", justify="right", style="cyan")
    node_table.add_column("Share", justify="right", style="dim")

    for ntype, count in sorted(stats["nodes_by_type"].items(), key=lambda x: x[1], reverse=True):
        pct = (count / stats["total_nodes"] * 100) if stats["total_nodes"] > 0 else 0
        node_table.add_row(ntype, f"{count:,}", f"{pct:.1f}%")
    node_table.add_section()
    node_table.add_row("[bold]Total Nodes[/bold]", f"[bold]{stats['total_nodes']:,}[/bold]", "100.0%")

    edge_table = Table(title="Ingested Edges by Relationship", box=box.ROUNDED, safe_box=True, header_style="bold blue")
    edge_table.add_column("Edge Type", style="bold")
    edge_table.add_column("Count", justify="right", style="green")
    edge_table.add_column("Share", justify="right", style="dim")

    for etype, count in sorted(stats["edges_by_type"].items(), key=lambda x: x[1], reverse=True):
        pct = (count / stats["total_edges"] * 100) if stats["total_edges"] > 0 else 0
        edge_table.add_row(etype, f"{count:,}", f"{pct:.1f}%")
    edge_table.add_section()
    edge_table.add_row("[bold]Total Edges[/bold]", f"[bold]{stats['total_edges']:,}[/bold]", "100.0%")

    console.print(node_table)
    console.print(edge_table)

    if warnings:
        console.print(f"[yellow]Warnings encountered during collection ({len(warnings)}):[/yellow]")
        for w in warnings[:5]:
            console.print(f"  [dim]- {w}[/dim]")
        if len(warnings) > 5:
            console.print(f"  [dim]... and {len(warnings) - 5} more.[/dim]")
    console.print()

# ----------------------------------------------------------------------
# arrow graph info
# ----------------------------------------------------------------------
graph_app = typer.Typer(help="Inspect and query the attack-path graph.")
app.add_typer(graph_app, name="graph")


@graph_app.command(name="info")
def graph_info(
    db: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        "-d",
        help="Path to SQLite database (default: ./arrow.db).",
        exists=True,
        file_okay=True,
        readable=True,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output graph statistics as JSON.",
    ),
) -> None:
    """Display graph metrics, node/edge distributions, and top connected objects."""
    if not db.exists():
        if json_output:
            console.print(json.dumps({"status": "error", "message": f"Database not found at '{db}'"}))
        else:
            console.print(f"[bold red]Error:[/bold red] Database file not found at '{db}'. Run `arrow ingest` first.")
        raise typer.Exit(code=1)

    try:
        graph = load_graph(db)
    except Exception as exc:
        if json_output:
            console.print(json.dumps({"status": "error", "message": str(exc)}))
        else:
            console.print(f"[bold red]Failed to load graph:[/bold red] {exc}")
        raise typer.Exit(code=1)

    stats = compute_graph_stats(graph, top_n=5)

    if json_output:
        payload = {
            "database": str(db.resolve()),
            **stats,
        }
        print(json.dumps(payload, indent=2))
        return

    total_nodes = stats["total_nodes"]
    total_edges = stats["total_edges"]

    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]Active Directory Graph Overview[/bold cyan]\n"
            f"[dim]Database:[/dim] [green]{db.resolve()}[/green]\n"
            f"[dim]Total Nodes:[/dim] [bold white]{total_nodes:,}[/bold white] | "
            f"[dim]Total Edges:[/dim] [bold white]{total_edges:,}[/bold white]\n"
            f"[dim]Graph Density:[/dim] [yellow]{stats['density']:.6f}[/yellow] | "
            f"[dim]Weakly Connected Components:[/dim] [yellow]{stats['weakly_connected_components']}[/yellow]\n"
            f"[dim]Isolated Nodes:[/dim] [yellow]{stats['isolated_nodes_count']}[/yellow]",
            title="[ Graph Statistics ]",
            border_style="cyan",
            box=box.ROUNDED,
            safe_box=True,
        )
    )

    node_table = Table(title="Nodes by Type", box=box.ROUNDED, safe_box=True, header_style="bold magenta")
    node_table.add_column("Type", style="bold")
    node_table.add_column("Count", justify="right", style="cyan")
    node_table.add_column("Share", justify="right", style="dim")

    for ntype, count in sorted(stats["nodes_by_type"].items(), key=lambda x: x[1], reverse=True):
        pct = (count / total_nodes * 100) if total_nodes > 0 else 0
        node_table.add_row(ntype, f"{count:,}", f"{pct:.1f}%")

    edge_table = Table(title="Edges by Relationship", box=box.ROUNDED, safe_box=True, header_style="bold blue")
    edge_table.add_column("Type", style="bold")
    edge_table.add_column("Count", justify="right", style="green")
    edge_table.add_column("Share", justify="right", style="dim")

    for etype, count in sorted(stats["edges_by_type"].items(), key=lambda x: x[1], reverse=True):
        pct = (count / total_edges * 100) if total_edges > 0 else 0
        edge_table.add_row(etype, f"{count:,}", f"{pct:.1f}%")

    console.print(node_table)
    console.print(edge_table)

    if stats["top_in_degree"]:
        in_table = Table(title="Top Inbound Targets (Most Referenced / High In-Degree)", box=box.ROUNDED, safe_box=True, header_style="bold yellow")
        in_table.add_column("Name", style="bold")
        in_table.add_column("Type", style="cyan")
        in_table.add_column("In-Degree", justify="right", style="bold green")
        in_table.add_column("SID", style="dim")
        for item in stats["top_in_degree"]:
            in_table.add_row(item["name"], item["type"], str(item["degree"]), item["objectid"])
        console.print(in_table)

    if stats["top_out_degree"]:
        out_table = Table(title="Top Outbound Principals (Most Privileges / High Out-Degree)", box=box.ROUNDED, safe_box=True, header_style="bold red")
        out_table.add_column("Name", style="bold")
        out_table.add_column("Type", style="cyan")
        out_table.add_column("Out-Degree", justify="right", style="bold green")
        out_table.add_column("SID", style="dim")
        for item in stats["top_out_degree"]:
            out_table.add_row(item["name"], item["type"], str(item["degree"]), item["objectid"])
        console.print(out_table)

    console.print()


# ----------------------------------------------------------------------
# arrow mark owned / unowned
# ----------------------------------------------------------------------
mark_app = typer.Typer(help="Manage owned compromised credentials.")
app.add_typer(mark_app, name="mark")


@mark_app.command(name="owned")
def mark_owned_cmd(
    name_or_sid: str = typer.Argument(..., help="Node name or SID to flag as owned/compromised."),
    db: Path = typer.Option(DEFAULT_DB_PATH, "--db", "-d", help="Path to SQLite database."),
    json_output: bool = typer.Option(False, "--json", help="Output result as JSON."),
) -> None:
    """Flag a node as 'owned' (compromised) and persist to database."""
    try:
        graph = load_graph(db)
        result = mark_node_owned(graph, db_path=db, identifier=name_or_sid, owned=True)
    except Exception as exc:
        if json_output:
            console.print(json.dumps({"status": "error", "message": str(exc)}))
        else:
            console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if json_output:
        print(json.dumps({"status": "success", "action": "mark_owned", **result}, indent=2))
    else:
        console.print(f"[bold green]✓ Marked as owned:[/bold green] [bold cyan]{result['name']}[/bold cyan] ({result['type']} | {result['objectid']})")


@mark_app.command(name="unowned")
def mark_unowned_cmd(
    name_or_sid: str = typer.Argument(..., help="Node name or SID to unmark."),
    db: Path = typer.Option(DEFAULT_DB_PATH, "--db", "-d", help="Path to SQLite database."),
    json_output: bool = typer.Option(False, "--json", help="Output result as JSON."),
) -> None:
    """Remove 'owned' flag from a node and persist to database."""
    try:
        graph = load_graph(db)
        result = mark_node_owned(graph, db_path=db, identifier=name_or_sid, owned=False)
    except Exception as exc:
        if json_output:
            print(json.dumps({"status": "error", "message": str(exc)}))
        else:
            console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if json_output:
        print(json.dumps({"status": "success", "action": "mark_unowned", **result}, indent=2))
    else:
        console.print(f"[bold yellow]✓ Unmarked owned status:[/bold yellow] [bold cyan]{result['name']}[/bold cyan] ({result['type']} | {result['objectid']})")


# ----------------------------------------------------------------------
# arrow list owned
# ----------------------------------------------------------------------
list_app = typer.Typer(help="List database entities.")
app.add_typer(list_app, name="list")


@list_app.command(name="owned")
def list_owned_cmd(
    db: Path = typer.Option(DEFAULT_DB_PATH, "--db", "-d", help="Path to SQLite database."),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON."),
) -> None:
    """Show current set of owned/compromised nodes."""
    try:
        graph = load_graph(db)
        owned_nodes = list_owned_nodes(graph)
    except Exception as exc:
        if json_output:
            print(json.dumps({"status": "error", "message": str(exc)}))
        else:
            console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if json_output:
        print(json.dumps({"total_owned": len(owned_nodes), "owned_nodes": owned_nodes}, indent=2))
        return

    if not owned_nodes:
        console.print("[yellow]No nodes are currently marked as owned. Use `arrow mark owned <name>`.[/yellow]")
        return

    table = Table(title=f"Owned Nodes ({len(owned_nodes)})", box=box.ROUNDED, safe_box=True, header_style="bold green")
    table.add_column("Name", style="bold")
    table.add_column("Type", style="cyan")
    table.add_column("Object ID / SID", style="dim")

    for node in owned_nodes:
        table.add_row(node["name"], node["type"], node["objectid"])

    console.print(table)


# ----------------------------------------------------------------------
# arrow path
# ----------------------------------------------------------------------
@app.command(name="path")
def path_cmd(
    start: str | None = typer.Argument(
        None,
        help="Starting node name or SID. If omitted, computes path from ANY owned node.",
    ),
    to: str = typer.Option(
        ...,
        "--to",
        "-t",
        help="Target node name or SID (e.g. 'Domain Admins', 'DC01.CORP.LOCAL').",
    ),
    stealth: bool = typer.Option(
        False,
        "--stealth",
        "-s",
        help="Use weighted shortest path favoring quiet relationships over noisy ones.",
    ),
    db: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        "-d",
        help="Path to SQLite database.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output attack path as JSON.",
    ),
) -> None:
    """Compute shortest or stealthiest attack path from start (or any owned node) to target."""
    try:
        graph = load_graph(db)
        result = find_path(graph, start=start, target=to, stealth=stealth)
    except Exception as exc:
        if json_output:
            print(json.dumps({"status": "error", "found": False, "message": str(exc)}))
        else:
            console.print(f"[bold red]Path error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    # Auto-save computed path to SQLite database for later explanation or auditing
    saved_path_id: int | None = None
    try:
        saved_path_id = save_computed_path(db, result)
    except Exception:
        saved_path_id = None

    if json_output:
        res_dict = result.to_dict()
        if saved_path_id is not None:
            res_dict["path_id"] = saved_path_id
        print(json.dumps({"status": "success", "found": True, **res_dict}, indent=2))
        return

    # Visual Rich Presentation
    console.print()
    mode_tag = "[bold yellow]⚡ STEALTH WEIGHTED[/bold yellow]" if stealth else "[bold cyan]🎯 UNWEIGHTED SHORTEST[/bold cyan]"
    saved_str = f" | [dim]Saved as Path ID:[/dim] [bold yellow]#{saved_path_id}[/bold yellow]" if saved_path_id else ""
    console.print(
        Panel.fit(
            f"{mode_tag}\n"
            f"[dim]Origin:[/dim] [bold white]{result.start['name']}[/bold white] ({result.start['type']})\n"
            f"[dim]Target:[/dim] [bold white]{result.target['name']}[/bold white] ({result.target['type']})\n"
            f"[dim]Total Hops:[/dim] [green]{result.hops}[/green] | "
            f"[dim]Total Weight (Noise):[/dim] [yellow]{result.total_weight:.1f}[/yellow]"
            f"{saved_str}",
            title="[ Attack Path Found ]",
            border_style="green",
            box=box.ROUNDED,
            safe_box=True,
        )
    )

    # Rendered chain
    console.print()
    console.print(
        Panel(
            f"[bold magenta]{result.chain}[/bold magenta]",
            title="Attack Path Chain",
            border_style="magenta",
            box=box.ROUNDED,
            safe_box=True,
        )
    )

    # Step-by-step breakdown table
    table = Table(title="Step-by-Step Traversal", box=box.ROUNDED, safe_box=True, header_style="bold blue")
    table.add_column("Step", justify="right", style="dim")
    table.add_column("Source", style="bold")
    table.add_column("Relationship", style="bold green")
    table.add_column("Target", style="bold")
    table.add_column("Weight", justify="right", style="cyan")
    table.add_column("Detection Risk", style="yellow")

    for seg in result.segments:
        table.add_row(
            str(seg.step),
            seg.source["name"],
            f"──[{seg.edge_type}]──>",
            seg.target["name"],
            f"{seg.weight:.1f}",
            seg.detection_risk,
        )

    console.print(table)
    if saved_path_id:
        console.print(f"[dim]Tip: Run '[bold cyan]arrow explain {saved_path_id}[/bold cyan]' to view human-readable attacker narrative with MITRE ATT&CK mappings.[/dim]")
    console.print()


# ----------------------------------------------------------------------
# arrow explain
# ----------------------------------------------------------------------
@app.command(name="explain")
def explain_cmd(
    path_ref: str | None = typer.Argument(
        None,
        help="Saved path ID (e.g. '1', 'path-1'), JSON string, raw path chain, or '-' to read from stdin.",
    ),
    format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: 'text' (Rich console UI) or 'md' (Markdown report suitable for copy-pasting).",
    ),
    llm: bool = typer.Option(
        False,
        "--llm",
        help="Use Anthropic Claude (claude-sonnet-4-6) to generate a natural senior red team narrative paragraph.",
    ),
    db: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        "-d",
        help="Path to SQLite database containing saved paths.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output explanation narrative as JSON.",
    ),
) -> None:
    """Turn a raw attack path into a human-readable, attacker-reasoning narrative with MITRE ATT&CK mappings."""
    raw_ref: str | None = path_ref

    # Check if input should be read from stdin
    if raw_ref == "-" or (raw_ref is None and not sys.stdin.isatty()):
        try:
            stdin_data = sys.stdin.read().strip()
            if stdin_data:
                raw_ref = stdin_data
        except Exception:
            pass

    if not raw_ref:
        err_msg = (
            "No path provided. Pass a saved path ID (e.g. 'arrow explain 1'), "
            "a raw chain, or pipe JSON output from 'arrow path'."
        )
        if json_output:
            print(json.dumps({"status": "error", "message": err_msg}))
        else:
            console.print(f"[bold red]Explain error:[/bold red] {err_msg}")
        raise typer.Exit(code=1)

    clean_ref = raw_ref.strip()
    path_payload: dict[str, Any] | None = None
    resolved_id: int | str | None = None

    # Option 1: Piped or passed JSON string
    if (clean_ref.startswith("{") and clean_ref.endswith("}")) or (clean_ref.startswith("[") and clean_ref.endswith("]")):
        try:
            parsed = json.loads(clean_ref)
            if isinstance(parsed, dict):
                # If wrapped in success response
                path_payload = parsed
                resolved_id = parsed.get("path_id")
            elif isinstance(parsed, list):
                path_payload = {"segments": parsed}
        except Exception as json_err:
            if json_output:
                print(json.dumps({"status": "error", "message": f"Failed to parse path JSON: {json_err}"}))
            else:
                console.print(f"[bold red]Explain error:[/bold red] Failed to parse path JSON: {json_err}")
            raise typer.Exit(code=1)

    # Option 2: Lookup saved path in SQLite by ID / slug
    if path_payload is None:
        saved = get_saved_path(db, clean_ref)
        if saved:
            path_payload = saved
            resolved_id = saved.get("path_id")
        elif "──[" in clean_ref or "->" in clean_ref:
            # Option 3: Raw textual chain
            path_payload = {"chain": clean_ref}
        else:
            # Unresolved reference
            if clean_ref.isdigit() or clean_ref.lower().startswith("path-") or clean_ref.startswith("#"):
                err_msg = f"Saved path ID '{clean_ref}' not found in database '{db}'."
            else:
                err_msg = f"Could not interpret '{clean_ref}' as a saved path ID, JSON payload, or path chain."

            if json_output:
                print(json.dumps({"status": "error", "message": err_msg}))
            else:
                console.print(f"[bold red]Explain error:[/bold red] {err_msg}")
            raise typer.Exit(code=1)

    try:
        explanation = explain_path(path_payload, path_id=resolved_id)
        if llm:
            llm_text = explain_path_llm(path_payload)
            if llm_text:
                explanation.llm_narrative = llm_text
            elif not json_output:
                console.print(
                    "[dim yellow]Notice: ANTHROPIC_API_KEY is not configured or API call unavailable. "
                    "Falling back gracefully to template-based narrative.[/dim yellow]\n"
                )
    except Exception as exc:
        if json_output:
            print(json.dumps({"status": "error", "message": str(exc)}))
        else:
            console.print(f"[bold red]Explain error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    # Output dispatch
    if json_output:
        print(json.dumps({"status": "success", **explanation.to_dict()}, indent=2))
        return

    if format.lower() in ("md", "markdown"):
        print(explanation.to_markdown())
        return

    # Rich Terminal Output (format == "text")
    console.print()
    id_label = f"#{explanation.path_id}" if explanation.path_id is not None else "N/A"
    console.print(
        Panel.fit(
            f"[bold cyan]Active Directory Attack Path Narrative Explanation[/bold cyan]\n"
            f"[dim]Path ID:[/dim] [bold yellow]{id_label}[/bold yellow] | "
            f"[dim]Total Hops:[/dim] [green]{explanation.hops_count}[/green] | "
            f"[dim]Total Noise Score:[/dim] [yellow]{explanation.total_noise_score:.1f}[/yellow]\n"
            f"[dim]Origin:[/dim] [bold white]{explanation.start_name}[/bold white] ({explanation.start_type})\n"
            f"[dim]Target:[/dim] [bold white]{explanation.target_name}[/bold white] ({explanation.target_type})\n"
            f"[dim]Detection Risk:[/dim] {explanation.get_risk_assessment()}",
            title="[ Attack Path Narrative ]",
            border_style="cyan",
            box=box.ROUNDED,
            safe_box=True,
        )
    )

    if explanation.llm_narrative:
        console.print()
        console.print(
            Panel(
                f"[bold white]{explanation.llm_narrative}[/bold white]",
                title="[ Senior Red Team Operator Narrative (Claude AI - claude-sonnet-4-6) ]",
                border_style="cyan",
                box=box.ROUNDED,
                safe_box=True,
            )
        )

    if explanation.chain:
        console.print()
        console.print(
            Panel(
                f"[bold magenta]{explanation.chain}[/bold magenta]",
                title="Graph Traversal Chain",
                border_style="magenta",
                box=box.ROUNDED,
                safe_box=True,
            )
        )

    # Render hop cards
    console.print()
    for hop in explanation.hops:
        hop_content = (
            f"[bold white]{hop.source_name}[/bold white] ({hop.source_type}) "
            f"──[[bold green]{hop.edge_type}[/bold green]]──> "
            f"[bold white]{hop.target_name}[/bold white] ({hop.target_type})\n\n"
            f"[bold yellow]MITRE ATT&CK:[/bold yellow] [bold cyan]{hop.mitre_id}[/bold cyan] - {hop.mitre_name}\n"
            f"[bold yellow]Noise / Detection Score:[/bold yellow] [yellow]{hop.noise_score:.1f}[/yellow]\n\n"
            f"[bold]Meaning & Abuse:[/bold]\n"
            f"  {hop.description}\n\n"
            f"[bold]Concrete Exploitation Technique:[/bold]\n"
            f"  {hop.technique}"
        )
        console.print(
            Panel(
                hop_content,
                title=f"[ Hop {hop.step} : {hop.edge_type} ]",
                border_style="blue",
                box=box.ROUNDED,
                safe_box=True,
            )
        )

    # Bottom summary panel
    console.print()
    console.print(
        Panel.fit(
            f"[bold white]{explanation.attack_chain_summary}[/bold white]",
            title="[ Attack Chain Summary ]",
            border_style="yellow",
            box=box.ROUNDED,
            safe_box=True,
        )
    )
    console.print()



# ----------------------------------------------------------------------
# arrow query <name>
# ----------------------------------------------------------------------
@app.command(name="query")
def query_cmd(
    name: str = typer.Argument(
        ...,
        help=f"Built-in named query: {', '.join(AVAILABLE_QUERIES)}",
    ),
    db: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        "-d",
        help="Path to SQLite database.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output query results as JSON.",
    ),
) -> None:
    """Run built-in named Active Directory security queries (kerberoastable, asrep, unconstrained, dcsync)."""
    try:
        graph = load_graph(db)
        records = run_named_query(graph, query_name=name)
    except Exception as exc:
        if json_output:
            print(json.dumps({"status": "error", "message": str(exc)}))
        else:
            console.print(f"[bold red]Query error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if json_output:
        payload = {
            "query": name.lower(),
            "count": len(records),
            "results": records,
        }
        print(json.dumps(payload, indent=2))
        return

    q = name.lower()
    table = Table(
        title=f"Query Results: {q.upper()} ({len(records)} found)",
        box=box.ROUNDED,
        safe_box=True,
        header_style="bold cyan",
    )

    if q == "kerberoastable":
        table.add_column("Account Name", style="bold")
        table.add_column("SPN Target", style="green")
        table.add_column("AdminCount", justify="center", style="yellow")
        table.add_column("SID", style="dim")
        for r in records:
            table.add_row(r["name"], r["spn"], "True" if r["admincount"] else "False", r["objectid"])

    elif q in ("asrep", "asreproastable"):
        table.add_column("Account Name", style="bold")
        table.add_column("PreAuth Required", justify="center", style="red")
        table.add_column("AdminCount", justify="center", style="yellow")
        table.add_column("SID", style="dim")
        for r in records:
            table.add_row(r["name"], "FALSE (Vulnerable)", "True" if r["admincount"] else "False", r["objectid"])

    elif q in ("unconstrained", "unconstraineddelegation"):
        table.add_column("Computer Name", style="bold")
        table.add_column("Operating System", style="cyan")
        table.add_column("High Value", justify="center", style="yellow")
        table.add_column("SID", style="dim")
        for r in records:
            table.add_row(r["name"], r["operatingsystem"], "True" if r["highvalue"] else "False", r["objectid"])

    elif q == "dcsync":
        table.add_column("Principal Name", style="bold")
        table.add_column("Principal Type", style="cyan")
        table.add_column("Domain Target", style="magenta")
        table.add_column("Privilege", style="bold green")
        table.add_column("SID", style="dim")
        for r in records:
            table.add_row(r["name"], r["type"], r["domain"], r["right"], r["objectid"])

    elif q == "esc1":
        table.add_column("Certificate Template", style="bold yellow")
        table.add_column("Vulnerability", style="bold red")
        table.add_column("Allowed Enrollees", style="cyan")
        table.add_column("EKUs", style="white")
        for r in records:
            table.add_row(r["name"], r["vulnerability"], r.get("enrollees", ""), r.get("ekus", ""))

    elif q == "esc4":
        table.add_column("Certificate Template", style="bold yellow")
        table.add_column("Vulnerability", style="bold red")
        table.add_column("Principal with Write Rights", style="bold cyan")
        table.add_column("Type", style="dim")
        table.add_column("Permission / ACE", style="bold green")
        for r in records:
            table.add_row(r["name"], r["vulnerability"], r.get("principal", ""), r.get("principal_type", ""), r.get("permission", ""))

    elif q == "esc8":
        table.add_column("Enterprise CA", style="bold yellow")
        table.add_column("Vulnerability", style="bold red")
        table.add_column("HTTP Enrollment URL", style="cyan")
        table.add_column("EPA Enforced", justify="center", style="bold red")
        table.add_column("SSL Required", justify="center", style="yellow")
        for r in records:
            epa = "TRUE" if r.get("epa_enabled") else "FALSE (Vulnerable)"
            ssl = "TRUE" if r.get("ssl_required") else "FALSE (Cleartext HTTP)"
            table.add_row(r["name"], r["vulnerability"], r.get("endpoint", ""), epa, ssl)

    elif q == "adcs":
        table.add_column("Object Name", style="bold")
        table.add_column("Type", style="cyan")
        table.add_column("Vulnerability Finding", style="bold red")
        for r in records:
            table.add_row(r["name"], r.get("type", "ADCS"), r.get("vulnerability", "ADCS Misconfiguration"))

    console.print()
    console.print(table)
    console.print()


# ----------------------------------------------------------------------
# arrow blast <user_or_group>
# ----------------------------------------------------------------------
@app.command(name="blast")
def blast_cmd(
    user_or_group: str = typer.Argument(
        ...,
        help="Principal name or SID to compute blast radius for.",
    ),
    to_da: bool = typer.Option(
        False,
        "--to-da",
        help="Highlight and verify whether Domain Admins is reachable in blast radius.",
    ),
    db: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        "-d",
        help="Path to SQLite database.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output blast radius tree as JSON.",
    ),
) -> None:
    """Compute all nodes reachable via outbound edges from a principal, grouped by hop distance."""
    try:
        graph = load_graph(db)
        data = compute_blast_radius(graph, user_or_group=user_or_group, to_da=to_da)
    except Exception as exc:
        if json_output:
            print(json.dumps({"status": "error", "message": str(exc)}))
        else:
            console.print(f"[bold red]Blast error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if json_output:
        print(json.dumps(data, indent=2))
        return

    # Rich Tree rendering
    source_info = data["source"]
    console.print()

    # Header Panel
    da_tag = ""
    if data["reaches_domain_admins"]:
        da_tag = f"\n[bold red]⚠️ DOMAIN ADMINS REACHABLE (within {data['da_target']['hop']} hops)![/bold red]"
    elif to_da:
        da_tag = "\n[bold green]✓ Domain Admins is NOT reachable from this principal.[/bold green]"

    console.print(
        Panel.fit(
            f"[bold cyan]Blast Radius Analysis[/bold cyan]\n"
            f"[dim]Principal:[/dim] [bold white]{source_info['name']}[/bold white] ({source_info['type']})\n"
            f"[dim]Reachable Entities:[/dim] [yellow]{data['total_reachable']}[/yellow] across [yellow]{data['max_hops']}[/yellow] hops"
            f"{da_tag}",
            title="[ Blast Radius Overview ]",
            border_style="red" if data["reaches_domain_admins"] else "cyan",
            box=box.ROUNDED,
            safe_box=True,
        )
    )

    tree = Tree(
        f"[bold white]{source_info['name']}[/bold white] ([cyan]{source_info['type']}[/cyan])",
        guide_style="dim",
    )

    for hop_num in sorted(data["hops"].keys()):
        node_list = data["hops"][hop_num]
        branch = tree.add(f"[bold yellow]Hop {hop_num}[/bold yellow] [dim]({len(node_list)} entities)[/dim]")
        for item in node_list:
            is_da = (
                "domain admin" in item["name"].lower()
                or item["objectid"].endswith("-512")
            )
            name_style = "[bold red]" if is_da else "[white]"
            da_badge = " [bold red]🎯 [DOMAIN ADMINS][/bold red]" if is_da else ""
            hv_badge = " [bold yellow]★[/bold yellow]" if item["is_highvalue"] and not is_da else ""
            branch.add(
                f"[dim]──[{item['incoming_edge']}]──>[/dim] "
                f"{name_style}{item['name']}[/{name_style.replace('[', '').replace(']', '')}] "
                f"([cyan]{item['type']}[/cyan]){da_badge}{hv_badge}"
            )

    console.print(tree)

    if to_da and data["reaches_domain_admins"] and data["da_path"]:
        console.print()
        path_str = " ──> ".join(f"{p['source']} ──[{p['edge_type']}]" for p in data["da_path"])
        path_str += f" ──> [bold red]{data['da_target']['name']}[/bold red]"
        console.print(
            Panel(
                f"[bold red]Fastest Path to Domain Admins:[/bold red]\n{path_str}",
                border_style="red",
                box=box.ROUNDED,
                safe_box=True,
            )
        )

    console.print()


# ----------------------------------------------------------------------
# arrow fix
# ----------------------------------------------------------------------
@app.command(name="fix")
def fix_cmd(
    target: str = typer.Option(
        "Domain Admins",
        "--target",
        "-t",
        help="Target node name or SID to disconnect (e.g. 'Domain Admins').",
    ),
    source: str | None = typer.Option(
        None,
        "--source",
        "-s",
        help="Optional initial compromise principal. If omitted, evaluates owned nodes or all entry principals.",
    ),
    max_fixes: int = typer.Option(
        10,
        "--max",
        "-m",
        help="Maximum number of recommended edge remediations.",
    ),
    db: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        "-d",
        help="Path to SQLite database.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output remediation plan as JSON.",
    ),
) -> None:
    """Compute minimum edge cut and prioritized remediation actions to sever paths to a target."""
    try:
        graph = load_graph(db)
        plan = compute_remediation_plan(
            graph,
            target=target,
            source=source,
            max_recommendations=max_fixes,
        )
    except Exception as exc:
        if json_output:
            print(json.dumps({"status": "error", "message": str(exc)}))
        else:
            console.print(f"[bold red]Fix error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if json_output:
        print(json.dumps({"status": "success", **plan.to_dict()}, indent=2))
        return

    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]Arrow Remediation Analysis: Minimum Edge Cut Optimization[/bold cyan]\n"
            f"[dim]Target Objective:[/dim] [bold white]{plan.target['name']}[/bold white] ({plan.target['type']})\n"
            f"[dim]Initial Compromise Sources:[/dim] [yellow]{len(plan.sources)}[/yellow] principals evaluated\n"
            f"[dim]Attack Paths Analyzed:[/dim] [green]{plan.total_paths_identified}[/green] total paths\n"
            f"[dim]Algorithm:[/dim] [dim white]{plan.algorithm}[/dim white]",
            title="[ Attack Path Remediation ]",
            border_style="cyan",
            box=box.ROUNDED,
            safe_box=True,
        )
    )

    if not plan.items:
        console.print("[yellow]No attack paths found reaching target; no edge cut required.[/yellow]")
        console.print()
        return

    table = Table(
        title=f"Recommended Edge Remediations ({len(plan.items)} recommended fixes)",
        box=box.ROUNDED,
        safe_box=True,
        header_style="bold magenta",
    )
    table.add_column("Rank", justify="center", style="bold yellow", width=6)
    table.add_column("Source Principal", style="bold white")
    table.add_column("Relationship", style="bold green")
    table.add_column("Target Object", style="bold white")
    table.add_column("Paths Cut", justify="right", style="cyan", width=10)
    table.add_column("Impact", justify="right", style="bold green", width=10)
    table.add_column("Plain-Language Remediation Action", style="white")

    for item in plan.items:
        table.add_row(
            f"#{item.rank}",
            item.source["name"],
            f"──[{item.edge_type}]──>",
            item.target["name"],
            str(item.paths_eliminated),
            f"{item.paths_eliminated_pct:.1f}%",
            item.remediation,
        )

    console.print()
    console.print(table)

    severed = plan.total_paths_identified - plan.paths_remaining
    overall_pct = (severed / plan.total_paths_identified * 100) if plan.total_paths_identified > 0 else 0
    console.print(
        Panel.fit(
            f"[bold green]✓ Remediating these {len(plan.items)} edges eliminates {severed} of {plan.total_paths_identified} paths "
            f"({overall_pct:.1f}% total path severance) toward {plan.target['name']}.[/bold green]",
            border_style="green",
            box=box.ROUNDED,
            safe_box=True,
        )
    )
    console.print()


# ----------------------------------------------------------------------
# arrow export
# ----------------------------------------------------------------------
@app.command(name="export")
def export_cmd(
    format: str = typer.Option(
        "mermaid",
        "--format",
        "-f",
        help="Export format: 'dot' (Graphviz) or 'mermaid' (Mermaid flowchart).",
    ),
    target: str | None = typer.Option(
        None,
        "--target",
        "-t",
        help="Optional target node to focus graph export around.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination file path (e.g. graph.dot or graph.mmd). If omitted, prints to console.",
    ),
    db: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        "-d",
        help="Path to SQLite database.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output exported graph string wrapped in JSON.",
    ),
) -> None:
    """Export attack path graph to Graphviz DOT or Mermaid diagram format."""
    try:
        graph = load_graph(db)
        sub = extract_key_paths_subgraph(graph, target=target, max_nodes=40)

        fmt = format.lower()
        if fmt in ("dot", "graphviz"):
            content = export_to_dot(sub)
        elif fmt in ("mermaid", "mmd"):
            content = export_to_mermaid(sub)
        else:
            raise ValueError(f"Unsupported format '{format}'. Supported formats: 'dot', 'mermaid'.")
    except Exception as exc:
        if json_output:
            print(json.dumps({"status": "error", "message": str(exc)}))
        else:
            console.print(f"[bold red]Export error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        if json_output:
            print(json.dumps({"status": "success", "format": fmt, "output": str(output.resolve()), "nodes": len(sub.nodes), "edges": len(sub.edges)}, indent=2))
        else:
            console.print(f"[bold green]✓ Exported {fmt.upper()} graph ({len(sub.nodes)} nodes, {len(sub.edges)} edges) to:[/bold green] [cyan]{output.resolve()}[/cyan]")
    else:
        if json_output:
            print(json.dumps({"status": "success", "format": fmt, "content": content}, indent=2))
        else:
            print(content)


# ----------------------------------------------------------------------
# arrow report
# ----------------------------------------------------------------------
@app.command(name="report")
def report_cmd(
    format: str = typer.Option(
        "md",
        "--format",
        "-f",
        help="Report format: 'md' (Markdown) or 'html' (Self-contained HTML report).",
    ),
    target: str = typer.Option(
        "Domain Admins",
        "--target",
        "-t",
        help="Target high-value entity to focus path analysis and remediation on.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination report file path. Defaults to 'arrow_report.md' or 'arrow_report.html'.",
    ),
    db: Path = typer.Option(
        DEFAULT_DB_PATH,
        "--db",
        "-d",
        help="Path to SQLite database.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output report generation metadata as JSON.",
    ),
) -> None:
    """Generate comprehensive security findings, attack path narrative, and remediation report."""
    fmt = format.lower()
    if fmt not in ("md", "markdown", "html"):
        err_msg = f"Unsupported report format '{format}'. Use 'md' or 'html'."
        if json_output:
            print(json.dumps({"status": "error", "message": err_msg}))
        else:
            console.print(f"[bold red]Report error:[/bold red] {err_msg}")
        raise typer.Exit(code=1)

    try:
        graph = load_graph(db)
        if fmt in ("md", "markdown"):
            report_content = generate_markdown_report(graph, target=target, db_name=str(db.name))
            default_name = "arrow_report.md"
        else:
            report_content = generate_html_report(graph, target=target, db_name=str(db.name))
            default_name = "arrow_report.html"

        target_file = output or Path(default_name)
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(report_content, encoding="utf-8")
    except Exception as exc:
        if json_output:
            print(json.dumps({"status": "error", "message": str(exc)}))
        else:
            console.print(f"[bold red]Report error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    file_size_kb = target_file.stat().st_size / 1024

    if json_output:
        print(
            json.dumps(
                {
                    "status": "success",
                    "format": fmt,
                    "target": target,
                    "output": str(target_file.resolve()),
                    "size_kb": round(file_size_kb, 1),
                },
                indent=2,
            )
        )
        return

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]✓ Arrow Security Assessment Report Generated Successfully[/bold green]\n"
            f"[dim]Format:[/dim] [bold white]{fmt.upper()}[/bold white]\n"
            f"[dim]Target Objective:[/dim] [bold cyan]{target}[/bold cyan]\n"
            f"[dim]File Destination:[/dim] [cyan]{target_file.resolve()}[/cyan] [dim]({file_size_kb:.1f} KB)[/dim]\n"
            f"[dim]Included Sections:[/dim] Executive Summary, Vulnerability Auditing, Attack Path Narrative, "
            f"Visual Diagram, Minimum Edge Cut Remediation Plan",
            title="[ Assessment Report Ready ]",
            border_style="green",
            box=box.ROUNDED,
            safe_box=True,
        )
    )
    console.print()


# ----------------------------------------------------------------------
# arrow demo
# ----------------------------------------------------------------------
@app.command(name="demo")
def demo_cmd(
    output_dir: Path = typer.Option(
        Path("."),
        "--output-dir",
        "-o",
        help="Directory to save generated demo database and report artifacts.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output demo execution results as JSON.",
    ),
) -> None:
    """Run an automated end-to-end demonstration (ingest -> path -> explain -> fix -> report)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    demo_db = output_dir / "arrow_demo.db"
    sample_zip = Path("samples/sample_bloodhound.zip")

    if not sample_zip.exists():
        if not json_output:
            console.print("[dim]Generating synthetic Active Directory dataset fixture...[/dim]")
        write_sample_zip(sample_zip)

    start_time = time.perf_counter()

    if not json_output:
        console.print()
        console.print(
            Panel.fit(
                "[bold cyan]🏹 Arrow: Automated End-to-End Active Directory Demonstration[/bold cyan]\n"
                "[dim]Running full pipeline:[/dim] [bold white]ingest[/bold white] ──> "
                "[bold white]path[/bold white] ──> [bold white]explain[/bold white] ──> "
                "[bold white]fix[/bold white] ──> [bold white]report[/bold white]",
                title="[ Arrow Demo ]",
                border_style="cyan",
                box=box.ROUNDED,
                safe_box=True,
            )
        )

    # 1. Ingest
    importer = BloodHoundImporter()
    graph = importer.import_path(sample_zip)
    save_graph(graph, db_path=demo_db, overwrite=True)

    # Mark victim_bob as owned for realistic demonstration
    mark_node_owned(graph, db_path=demo_db, identifier="victim_bob", owned=True)

    # 2. Path Finding
    path_result = find_path(graph, start="victim_bob", target="Domain Admins", stealth=True)
    save_computed_path(demo_db, path_result)

    # 3. Explain Narrative
    explanation = explain_path(path_result, path_id=1)

    # 4. Remediation Plan
    remediation_plan = compute_remediation_plan(graph, target="Domain Admins")

    # 5. Reports & Exports
    html_report_path = output_dir / "arrow_demo_report.html"
    md_report_path = output_dir / "arrow_demo_report.md"
    mermaid_path = output_dir / "arrow_demo_graph.mermaid"
    dot_path = output_dir / "arrow_demo_graph.dot"

    html_content = generate_html_report(graph, target="Domain Admins", db_name=str(demo_db.name))
    md_content = generate_markdown_report(graph, target="Domain Admins", db_name=str(demo_db.name))
    sub = extract_key_paths_subgraph(graph, target="Domain Admins", max_nodes=25)

    html_report_path.write_text(html_content, encoding="utf-8")
    md_report_path.write_text(md_content, encoding="utf-8")
    mermaid_path.write_text(export_to_mermaid(sub), encoding="utf-8")
    dot_path.write_text(export_to_dot(sub), encoding="utf-8")

    elapsed = time.perf_counter() - start_time

    if json_output:
        payload = {
            "status": "success",
            "demo_database": str(demo_db.resolve()),
            "elapsed_seconds": round(elapsed, 3),
            "attack_path": path_result.to_dict(),
            "explanation": explanation.to_dict(),
            "remediation": remediation_plan.to_dict(),
            "generated_reports": {
                "html": str(html_report_path.resolve()),
                "markdown": str(md_report_path.resolve()),
                "mermaid": str(mermaid_path.resolve()),
                "dot": str(dot_path.resolve()),
            },
        }
        print(json.dumps(payload, indent=2))
        return

    # Rich Visual Steps
    console.print()
    console.print(f"[bold green]1. Ingestion Complete:[/bold green] Ingested [cyan]{len(graph.nodes)}[/cyan] nodes and [cyan]{len(graph.edges)}[/cyan] edges into [yellow]{demo_db}[/yellow]")
    console.print(f"[bold green]2. Attack Path Found:[/bold green] [bold magenta]{path_result.chain}[/bold magenta] ([green]{path_result.hops}[/green] hops, noise: [yellow]{path_result.total_weight:.1f}[/yellow])")
    console.print(f"[bold green]3. Narrative Explained:[/bold green] [bold white]{explanation.attack_chain_summary}[/bold white]")

    top_fix = remediation_plan.items[0] if remediation_plan.items else None
    if top_fix:
        console.print(f"[bold green]4. Key Remediation (Min-Cut):[/bold green] [yellow]#{top_fix.rank}[/yellow] [bold white]{top_fix.remediation}[/bold white] (Eliminates [cyan]{top_fix.paths_eliminated}[/cyan] paths, [green]{top_fix.paths_eliminated_pct:.1f}%[/green])")

    console.print(
        f"[bold green]5. Reports Exported:[/bold green]\n"
        f"   - HTML Report:     [cyan]{html_report_path.resolve()}[/cyan]\n"
        f"   - Markdown Report: [cyan]{md_report_path.resolve()}[/cyan]\n"
        f"   - Mermaid Diagram: [cyan]{mermaid_path.resolve()}[/cyan]\n"
        f"   - Graphviz DOT:    [cyan]{dot_path.resolve()}[/cyan]"
    )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]✓ Demo Finished in {elapsed:.2f} seconds![/bold green]\n"
            f"Open [cyan]{html_report_path.resolve()}[/cyan] in your browser to view the interactive assessment report.",
            border_style="green",
            box=box.ROUNDED,
            safe_box=True,
        )
    )
    console.print()


if __name__ == "__main__":
    app()

