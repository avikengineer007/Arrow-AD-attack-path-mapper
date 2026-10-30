"""SQLite persistence layer for Arrow graph models."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import networkx as nx


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS nodes (
    objectid TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    properties_json TEXT
);

CREATE TABLE IF NOT EXISTS edges (
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    properties_json TEXT
);

CREATE TABLE IF NOT EXISTS paths (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_name TEXT NOT NULL,
    target_name TEXT NOT NULL,
    hops INTEGER NOT NULL,
    total_weight REAL NOT NULL,
    stealth INTEGER NOT NULL,
    chain TEXT NOT NULL,
    result_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target);
CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(edge_type);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
CREATE INDEX IF NOT EXISTS idx_paths_created ON paths(created_at);
"""


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    """Open or create a SQLite database connection with row factory enabled."""
    path = Path(db_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def init_db(db_path: str | Path) -> None:
    """Initialize database tables and indexes."""
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.commit()


def save_graph(
    graph: nx.MultiDiGraph,
    db_path: str | Path,
    overwrite: bool = True,
) -> tuple[int, int]:
    """
    Persist a NetworkX MultiDiGraph to SQLite.

    Args:
        graph: NetworkX MultiDiGraph containing nodes and edges.
        db_path: Path to the SQLite database file.
        overwrite: If True, clears existing tables before inserting.

    Returns:
        tuple[int, int]: (node_count, edge_count) written.
    """
    init_db(db_path)
    with get_connection(db_path) as conn:
        if overwrite:
            conn.execute("DELETE FROM edges;")
            conn.execute("DELETE FROM nodes;")

        node_rows: list[tuple[str, str, str, str]] = []
        for node_id, data in graph.nodes(data=True):
            node_type = str(data.get("type", "Unknown"))
            node_name = str(data.get("name", node_id))
            # Extract remaining properties
            props = data.get("properties")
            if props is None:
                props = {k: v for k, v in data.items() if k not in ("type", "name", "objectid")}
            props_json = json.dumps(props, default=str)
            node_rows.append((str(node_id), node_type, node_name, props_json))

        conn.executemany(
            """
            INSERT OR REPLACE INTO nodes (objectid, type, name, properties_json)
            VALUES (?, ?, ?, ?);
            """,
            node_rows,
        )

        edge_rows: list[tuple[str, str, str, str]] = []
        for u, v, data in graph.edges(data=True):
            edge_type = str(data.get("edge_type", "Unknown"))
            props = data.get("properties")
            if props is None:
                props = {k: v for k, v in data.items() if k not in ("edge_type",)}
            props_json = json.dumps(props, default=str)
            edge_rows.append((str(u), str(v), edge_type, props_json))

        conn.executemany(
            """
            INSERT INTO edges (source, target, edge_type, properties_json)
            VALUES (?, ?, ?, ?);
            """,
            edge_rows,
        )
        conn.commit()

    return len(node_rows), len(edge_rows)


def load_graph(db_path: str | Path) -> nx.MultiDiGraph:
    """
    Load a NetworkX MultiDiGraph from SQLite.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        nx.MultiDiGraph: Reconstructed graph.
    """
    path = Path(db_path)
    if not path.exists():
        raise FileNotFoundError(f"Database not found at '{path}'")

    graph = nx.MultiDiGraph()
    with get_connection(db_path) as conn:
        # Load nodes
        node_cur = conn.execute("SELECT objectid, type, name, properties_json FROM nodes;")
        for row in node_cur:
            objectid = row["objectid"]
            node_type = row["type"]
            name = row["name"]
            props_raw = row["properties_json"]
            props: dict[str, Any] = {}
            if props_raw:
                try:
                    props = json.loads(props_raw)
                except Exception:
                    props = {}
            node_attrs = dict(props)
            node_attrs.update({
                "objectid": objectid,
                "type": node_type,
                "name": name,
                "properties": props,
            })
            graph.add_node(objectid, **node_attrs)

        # Load edges
        edge_cur = conn.execute("SELECT source, target, edge_type, properties_json FROM edges;")
        for row in edge_cur:
            src = row["source"]
            dst = row["target"]
            edge_type = row["edge_type"]
            props_raw = row["properties_json"]
            props = {}
            if props_raw:
                try:
                    props = json.loads(props_raw)
                except Exception:
                    props = {}
            edge_attrs = dict(props)
            edge_attrs.update({
                "edge_type": edge_type,
                "properties": props,
            })
            graph.add_edge(src, dst, key=edge_type, **edge_attrs)

    return graph


def get_db_counts(db_path: str | Path) -> dict[str, Any]:
    """Get node and edge counts aggregated by type directly from SQLite."""
    path = Path(db_path)
    if not path.exists():
        raise FileNotFoundError(f"Database not found at '{path}'")

    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT type, COUNT(*) as cnt FROM nodes GROUP BY type ORDER BY cnt DESC;")
        node_counts = {row["type"]: int(row["cnt"]) for row in cur.fetchall()}

        cur = conn.execute("SELECT edge_type, COUNT(*) as cnt FROM edges GROUP BY edge_type ORDER BY cnt DESC;")
        edge_counts = {row["edge_type"]: int(row["cnt"]) for row in cur.fetchall()}

        total_nodes = sum(node_counts.values())
        total_edges = sum(edge_counts.values())

    return {
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "nodes_by_type": node_counts,
        "edges_by_type": edge_counts,
    }


def update_node_property(
    db_path: str | Path,
    objectid: str,
    key: str,
    value: Any,
) -> tuple[str, str]:
    """
    Update a property in a node's properties_json in SQLite.

    Returns:
        tuple[str, str]: (objectid, name) of updated node.
    """
    path = Path(db_path)
    if not path.exists():
        raise FileNotFoundError(f"Database not found at '{path}'")

    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT objectid, name, properties_json FROM nodes WHERE objectid = ?;", (objectid,))
        row = cur.fetchone()
        if not row:
            raise KeyError(f"Node '{objectid}' not found in database.")

        name = row["name"]
        props_raw = row["properties_json"]
        props: dict[str, Any] = {}
        if props_raw:
            try:
                props = json.loads(props_raw)
            except Exception:
                props = {}

        if value is None:
            props.pop(key, None)
        else:
            props[key] = value

        conn.execute(
            "UPDATE nodes SET properties_json = ? WHERE objectid = ?;",
            (json.dumps(props, default=str), objectid),
        )
        conn.commit()

    return objectid, name


def get_owned_nodes_from_db(db_path: str | Path) -> list[dict[str, Any]]:
    """Retrieve all nodes flagged as owned from SQLite."""
    path = Path(db_path)
    if not path.exists():
        raise FileNotFoundError(f"Database not found at '{path}'")

    results: list[dict[str, Any]] = []
    with get_connection(db_path) as conn:
        cur = conn.execute("SELECT objectid, type, name, properties_json FROM nodes;")
        for row in cur:
            props_raw = row["properties_json"]
            if not props_raw or '"owned"' not in props_raw:
                continue
            try:
                props = json.loads(props_raw)
            except Exception:
                continue
            if props.get("owned") is True:
                results.append({
                    "objectid": row["objectid"],
                    "type": row["type"],
                    "name": row["name"],
                    "properties": props,
                })

    return results


def save_computed_path(
    db_path: str | Path,
    path_result: dict[str, Any] | Any,
) -> int:
    """
    Save a computed attack path to SQLite and return its auto-increment ID.

    Args:
        db_path: Path to SQLite database.
        path_result: PathResult instance or dict.

    Returns:
        int: Assigned path ID.
    """
    init_db(db_path)

    if hasattr(path_result, "to_dict"):
        data = path_result.to_dict()
    elif isinstance(path_result, dict):
        data = dict(path_result)
    else:
        raise ValueError(f"Unsupported path result type: {type(path_result).__name__}")

    start = data.get("start", {})
    target = data.get("target", {})
    source_name = str(start.get("name", "Unknown"))
    target_name = str(target.get("name", "Unknown"))
    hops = int(data.get("hops", 0))
    total_weight = float(data.get("total_weight", 0.0))
    stealth = 1 if data.get("stealth") else 0
    chain = str(data.get("chain", ""))
    result_json = json.dumps(data, default=str)

    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO paths (source_name, target_name, hops, total_weight, stealth, chain, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (source_name, target_name, hops, total_weight, stealth, chain, result_json),
        )
        conn.commit()
        path_id = cur.lastrowid

    return int(path_id) if path_id is not None else 1


def get_saved_path(
    db_path: str | Path,
    path_id: int | str,
) -> dict[str, Any] | None:
    """
    Retrieve a previously computed and saved path by ID from SQLite.

    Args:
        db_path: Path to SQLite database.
        path_id: Numeric ID (e.g. 1 or '1') or slug (e.g. 'path-1' or '#1').

    Returns:
        dict representation of saved path, or None if not found.
    """
    path = Path(db_path)
    if not path.exists():
        return None

    # Ensure table exists
    init_db(db_path)

    # Normalize path_id string
    cleaned_id = str(path_id).strip().lower()
    if cleaned_id.startswith("path-"):
        cleaned_id = cleaned_id[5:]
    elif cleaned_id.startswith("path_"):
        cleaned_id = cleaned_id[5:]
    elif cleaned_id.startswith("#"):
        cleaned_id = cleaned_id[1:]

    try:
        numeric_id = int(cleaned_id)
    except ValueError:
        return None

    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT id, created_at, source_name, target_name, hops, total_weight, stealth, chain, result_json
            FROM paths
            WHERE id = ?;
            """,
            (numeric_id,),
        )
        row = cur.fetchone()
        if not row:
            return None

        result_raw = row["result_json"]
        try:
            path_dict = json.loads(result_raw)
        except Exception:
            path_dict = {
                "source": {"name": row["source_name"]},
                "target": {"name": row["target_name"]},
                "hops": row["hops"],
                "total_weight": row["total_weight"],
                "stealth": bool(row["stealth"]),
                "chain": row["chain"],
                "segments": [],
            }

        path_dict["path_id"] = row["id"]
        path_dict["created_at"] = str(row["created_at"])
        return path_dict


def list_saved_paths(
    db_path: str | Path,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Retrieve metadata of recently saved attack paths from SQLite."""
    path = Path(db_path)
    if not path.exists():
        return []

    init_db(db_path)

    results: list[dict[str, Any]] = []
    with get_connection(db_path) as conn:
        cur = conn.execute(
            """
            SELECT id, created_at, source_name, target_name, hops, total_weight, stealth, chain
            FROM paths
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,),
        )
        for row in cur:
            results.append({
                "id": row["id"],
                "created_at": str(row["created_at"]),
                "source_name": row["source_name"],
                "target_name": row["target_name"],
                "hops": row["hops"],
                "total_weight": row["total_weight"],
                "stealth": bool(row["stealth"]),
                "chain": row["chain"],
            })

    return results

