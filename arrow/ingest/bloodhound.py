"""BloodHound JSON / Zip Importer for Arrow."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

import networkx as nx

from arrow.graph import EDGE_TYPES, NODE_TYPES, add_ad_edge, add_ad_node, create_empty_graph


# Canonical edge type lookup dictionary (case-insensitive)
EDGE_NAME_MAP: dict[str, str] = {
    "memberof": "MemberOf",
    "adminto": "AdminTo",
    "localadmin": "AdminTo",
    "localadmins": "AdminTo",
    "hassession": "HasSession",
    "session": "HasSession",
    "sessions": "HasSession",
    "genericall": "GenericAll",
    "genericwrite": "GenericWrite",
    "writedacl": "WriteDacl",
    "writeowner": "WriteOwner",
    "forcechangepassword": "ForceChangePassword",
    "user-force-change-password": "ForceChangePassword",
    "addmember": "AddMember",
    "add-member": "AddMember",
    "owns": "Owns",
    "owner": "Owns",
    "canrdp": "CanRDP",
    "remotedesktop": "CanRDP",
    "remotedesktopusers": "CanRDP",
    "allowedtodelegate": "AllowedToDelegate",
    "allowedtoact": "AllowedToAct",
    "dcsync": "DCSync",
    "sqladmin": "SQLAdmin",
    "sqladmins": "SQLAdmin",
    "adcsenroll": "ADCSEnroll",
    "enroll": "ADCSEnroll",
    "adcsvulnerabletemplate": "ADCSVulnerableTemplate",
    "adcshostrelay": "ADCSHostRelay",
}

# Mapping file type / meta type to canonical Node type
TYPE_MAPPING: dict[str, str] = {
    "users": "User",
    "user": "User",
    "groups": "Group",
    "group": "Group",
    "computers": "Computer",
    "computer": "Computer",
    "domains": "Domain",
    "domain": "Domain",
    "gpos": "GPO",
    "gpo": "GPO",
    "ous": "OU",
    "ou": "OU",
    "certtemplates": "CertTemplate",
    "certtemplate": "CertTemplate",
    "cas": "EnterpriseCA",
    "enterprisecas": "EnterpriseCA",
    "enterpriseca": "EnterpriseCA",
}


def normalize_edge_type(raw_type: str) -> str | None:
    """Normalize raw edge type or right name to canonical schema edge type."""
    cleaned = raw_type.strip().lower().replace(" ", "").replace("_", "")
    return EDGE_NAME_MAP.get(cleaned)


def _extract_sid(obj: Any) -> str | None:
    """Helper to extract an object SID/ID from varied SharpHound formats."""
    if isinstance(obj, str):
        return obj.strip()
    if isinstance(obj, dict):
        for key in (
            "ObjectIdentifier",
            "objectid",
            "ObjectId",
            "SID",
            "sid",
            "PrincipalSID",
            "UserId",
            "UserSids",
            "UserSid",
            "domainsid",
        ):
            val = obj.get(key)
            if val and isinstance(val, str):
                return val.strip()
    return None


# Safety ceilings for archive decompression (Zip Bomb defense)
MAX_UNCOMPRESSED_FILE_BYTES: int = 500 * 1024 * 1024  # 500 MB per file
MAX_UNCOMPRESSED_ARCHIVE_BYTES: int = 2 * 1024 * 1024 * 1024  # 2 GB total


class BloodHoundImporter:
    """Importer for SharpHound / BloodHound JSON and ZIP data archives."""

    def __init__(self, target_graph: nx.MultiDiGraph | None = None) -> None:
        self.graph: nx.MultiDiGraph = target_graph if target_graph is not None else create_empty_graph()
        self.ingested_files: list[str] = []
        self.warnings: list[str] = []

    def import_path(self, path: str | Path) -> nx.MultiDiGraph:
        """
        Import BloodHound data from a .zip archive, directory, or individual .json file.

        Args:
            path: Path to archive or file.

        Returns:
            Populated NetworkX MultiDiGraph.
        """
        src = Path(path)
        if not src.exists():
            raise FileNotFoundError(f"Path does not exist: '{src}'")

        if src.is_file() and zipfile.is_zipfile(src):
            self._import_from_zip(src)
        elif src.is_dir():
            self._import_from_dir(src)
        elif src.is_file() and src.suffix.lower() == ".json":
            with open(src, "r", encoding="utf-8-sig") as f:
                self._import_json_data(json.load(f), file_hint=src.name)
        else:
            raise ValueError(f"Unsupported file format for '{src}'. Expected .zip or .json file/directory.")

        return self.graph

    def _import_from_zip(self, zip_path: Path) -> None:
        total_extracted_bytes = 0

        with zipfile.ZipFile(zip_path, "r") as archive:
            for file_info in archive.infolist():
                if file_info.is_dir() or not file_info.filename.lower().endswith(".json"):
                    continue
                # Skip macOS metadata or hidden files
                if "__MACOSX" in file_info.filename or Path(file_info.filename).name.startswith("._"):
                    continue

                # Primary defense: pre-read file_size check from ZIP header
                if file_info.file_size > MAX_UNCOMPRESSED_FILE_BYTES:
                    self.warnings.append(
                        f"Skipping '{file_info.filename}': decompressed size ({file_info.file_size:,} bytes) "
                        f"exceeds safety ceiling ({MAX_UNCOMPRESSED_FILE_BYTES:,} bytes)."
                    )
                    continue

                if total_extracted_bytes + file_info.file_size > MAX_UNCOMPRESSED_ARCHIVE_BYTES:
                    self.warnings.append(
                        f"Aborting archive extraction: cumulative size exceeds safety limit "
                        f"({MAX_UNCOMPRESSED_ARCHIVE_BYTES:,} bytes)."
                    )
                    break

                try:
                    # Bounded streaming read (protects against forged ZIP header file_size)
                    raw_chunks = []
                    file_bytes_read = 0
                    with archive.open(file_info) as file_handle:
                        while True:
                            chunk = file_handle.read(64 * 1024)
                            if not chunk:
                                break
                            file_bytes_read += len(chunk)
                            total_extracted_bytes += len(chunk)
                            if file_bytes_read > MAX_UNCOMPRESSED_FILE_BYTES:
                                raise ValueError(
                                    f"Decompressed stream exceeded size limit ({MAX_UNCOMPRESSED_FILE_BYTES:,} bytes)."
                                )
                            if total_extracted_bytes > MAX_UNCOMPRESSED_ARCHIVE_BYTES:
                                raise ValueError(
                                    f"Cumulative decompressed size exceeded safety limit ({MAX_UNCOMPRESSED_ARCHIVE_BYTES:,} bytes)."
                                )
                            raw_chunks.append(chunk)

                    content = b"".join(raw_chunks).decode("utf-8-sig")
                    data = json.loads(content)
                    self._import_json_data(data, file_hint=Path(file_info.filename).name)
                    self.ingested_files.append(file_info.filename)
                except MemoryError:
                    self.warnings.append(
                        f"Memory limit reached while parsing '{file_info.filename}'. Skipping file to prevent termination."
                    )
                except Exception as ex:
                    self.warnings.append(f"Failed to parse '{file_info.filename}' in zip: {ex}")

    def _import_from_dir(self, dir_path: Path) -> None:
        for json_file in sorted(dir_path.glob("*.json")):
            try:
                file_size = json_file.stat().st_size
                if file_size > MAX_UNCOMPRESSED_FILE_BYTES:
                    self.warnings.append(
                        f"Skipping '{json_file.name}': file size ({file_size:,} bytes) exceeds limit."
                    )
                    continue
                with open(json_file, "r", encoding="utf-8-sig") as f:
                    data = json.load(f)
                self._import_json_data(data, file_hint=json_file.name)
                self.ingested_files.append(json_file.name)
            except MemoryError:
                self.warnings.append(
                    f"Memory limit reached while parsing '{json_file.name}'. Skipping file to prevent termination."
                )
            except Exception as ex:
                self.warnings.append(f"Failed to parse '{json_file.name}': {ex}")

    def _import_json_data(self, data: Any, file_hint: str) -> None:
        """Parse structured data from a single JSON payload."""
        items: list[dict[str, Any]] = []
        meta_type: str | None = None

        if isinstance(data, dict):
            meta = data.get("meta", {})
            if isinstance(meta, dict):
                meta_type = meta.get("type")

            # BloodHound v4+ wrapper: {"data": [...], "meta": {...}}
            if "data" in data and isinstance(data["data"], list):
                items = data["data"]
            # BloodHound v3 format: {"users": [...], "meta": ...}
            else:
                for key, val in data.items():
                    if key.lower() in TYPE_MAPPING and isinstance(val, list):
                        items = val
                        meta_type = key.lower()
                        break
        elif isinstance(data, list):
            items = data

        # Inferred node type
        inferred_type = self._resolve_type(file_hint, meta_type)

        # First pass: Ingest all nodes
        for item in items:
            if not isinstance(item, dict):
                continue
            self._parse_node(item, default_type=inferred_type)

        # Second pass: Ingest all relationships / edges
        for item in items:
            if not isinstance(item, dict):
                continue
            self._parse_edges(item, node_type=inferred_type)

    def _resolve_type(self, file_hint: str, meta_type: str | None) -> str:
        """Determine AD node type from meta or filename."""
        if meta_type and meta_type.lower() in TYPE_MAPPING:
            return TYPE_MAPPING[meta_type.lower()]

        hint_lower = file_hint.lower()
        for token, ntype in TYPE_MAPPING.items():
            if token in hint_lower:
                return ntype

        return "Unknown"

    def _parse_node(self, item: dict[str, Any], default_type: str) -> str | None:
        """Extract node metadata and insert into graph."""
        props = item.get("Properties")
        if not isinstance(props, dict):
            props = {}

        # Determine objectid (SID)
        objectid = (
            item.get("ObjectIdentifier")
            or props.get("objectid")
            or item.get("objectid")
            or props.get("domainsid")
            or item.get("domainsid")
        )

        if not objectid or not isinstance(objectid, str):
            return None

        objectid = objectid.strip()

        # Determine name
        name = (
            props.get("name")
            or item.get("name")
            or props.get("distinguishedname")
            or item.get("distinguishedname")
            or objectid
        )

        # Determine node type
        node_type = default_type
        if node_type == "Unknown":
            raw_type = item.get("ObjectType") or props.get("type") or item.get("type")
            if raw_type and isinstance(raw_type, str) and raw_type.lower() in TYPE_MAPPING:
                node_type = TYPE_MAPPING[raw_type.lower()]
            elif node_type not in NODE_TYPES:
                node_type = "Unknown"

        # Combine extra attributes, filtering out sub-lists/collections
        clean_props: dict[str, Any] = {}
        for k, v in props.items():
            if k.lower() not in ("objectid", "domainsid") and not isinstance(v, (list, dict)):
                clean_props[k] = v

        for k, v in item.items():
            if k not in (
                "ObjectIdentifier",
                "objectid",
                "Properties",
                "Aces",
                "Members",
                "Sessions",
                "LocalAdmins",
                "RemoteDesktop",
                "RemoteDesktopUsers",
                "AllowedToDelegate",
                "AllowedToAct",
                "SQLAdmin",
                "SqlAdmins",
            ) and not isinstance(v, (list, dict)):
                clean_props[k] = v

        add_ad_node(
            self.graph,
            objectid=objectid,
            node_type=node_type,
            name=str(name),
            properties=clean_props,
        )
        return objectid

    def _parse_edges(self, item: dict[str, Any], node_type: str) -> None:
        """Extract relationships and add directed edges."""
        props = item.get("Properties") if isinstance(item.get("Properties"), dict) else {}
        current_id = (
            item.get("ObjectIdentifier")
            or props.get("objectid")
            or item.get("objectid")
            or props.get("domainsid")
            or item.get("domainsid")
        )
        if not current_id or not isinstance(current_id, str):
            return
        current_id = current_id.strip()

        # 1. Group Members: member -> MemberOf -> group
        members = item.get("Members")
        if isinstance(members, list):
            for m in members:
                member_sid = _extract_sid(m)
                if member_sid:
                    member_type = m.get("ObjectType", "Unknown") if isinstance(m, dict) else "Unknown"
                    if member_type in TYPE_MAPPING:
                        member_type = TYPE_MAPPING[member_type.lower()]
                    if member_sid not in self.graph:
                        add_ad_node(self.graph, member_sid, node_type=member_type)
                    add_ad_edge(self.graph, source=member_sid, target=current_id, edge_type="MemberOf")

        # 2. MemberOf explicitly on User/Computer/Group
        member_of = item.get("MemberOf") or props.get("memberof")
        if isinstance(member_of, list):
            for g in member_of:
                group_sid = _extract_sid(g)
                if group_sid:
                    if group_sid not in self.graph:
                        add_ad_node(self.graph, group_sid, node_type="Group")
                    add_ad_edge(self.graph, source=current_id, target=group_sid, edge_type="MemberOf")

        # PrimaryGroupSID
        primary_group_sid = props.get("primarygroupsid") or item.get("PrimaryGroupSID")
        if primary_group_sid and isinstance(primary_group_sid, str):
            primary_group_sid = primary_group_sid.strip()
            if primary_group_sid not in self.graph:
                add_ad_node(self.graph, primary_group_sid, node_type="Group")
            add_ad_edge(self.graph, source=current_id, target=primary_group_sid, edge_type="MemberOf")

        # 3. LocalAdmins: admin -> AdminTo -> computer
        local_admins = self._unpack_results(item.get("LocalAdmins"))
        for admin in local_admins:
            admin_sid = _extract_sid(admin)
            if admin_sid:
                add_ad_edge(self.graph, source=admin_sid, target=current_id, edge_type="AdminTo")

        # 4. Sessions: computer -> HasSession -> user
        # In BloodHound attack paths, having control of a computer allows compromising
        # sessions of logged-in users on that computer.
        sessions = self._unpack_results(item.get("Sessions"))
        for session in sessions:
            user_sid = _extract_sid(session)
            comp_sid = None
            if isinstance(session, dict):
                comp_sid = session.get("ComputerId") or session.get("ComputerSID")
            source_comp = str(comp_sid).strip() if comp_sid else current_id
            if user_sid:
                if user_sid not in self.graph:
                    add_ad_node(self.graph, user_sid, node_type="User")
                add_ad_edge(self.graph, source=source_comp, target=user_sid, edge_type="HasSession")

        # 5. RemoteDesktop / RemoteDesktopUsers -> CanRDP
        rdp_entries = self._unpack_results(item.get("RemoteDesktop") or item.get("RemoteDesktopUsers"))
        for rdp in rdp_entries:
            rdp_sid = _extract_sid(rdp)
            if rdp_sid:
                add_ad_edge(self.graph, source=rdp_sid, target=current_id, edge_type="CanRDP")

        # 6. AllowedToDelegate: source -> AllowedToDelegate -> target
        delegates = self._unpack_results(item.get("AllowedToDelegate"))
        for d in delegates:
            target_sid = _extract_sid(d)
            if target_sid:
                add_ad_edge(self.graph, source=current_id, target=target_sid, edge_type="AllowedToDelegate")

        # 7. AllowedToAct: principal -> AllowedToAct -> computer
        allowed_act = self._unpack_results(item.get("AllowedToAct"))
        for act in allowed_act:
            principal_sid = _extract_sid(act)
            if principal_sid:
                add_ad_edge(self.graph, source=principal_sid, target=current_id, edge_type="AllowedToAct")

        # 8. SQLAdmin: principal -> SQLAdmin -> computer
        sql_admins = self._unpack_results(item.get("SQLAdmin") or item.get("SqlAdmins"))
        for sqla in sql_admins:
            principal_sid = _extract_sid(sqla)
            if principal_sid:
                add_ad_edge(self.graph, source=principal_sid, target=current_id, edge_type="SQLAdmin")

        # 9. Aces (Access Control Entries)
        aces = item.get("Aces")
        if isinstance(aces, list):
            domain_replication_rights: dict[str, set[str]] = {}

            for ace in aces:
                if not isinstance(ace, dict):
                    continue
                principal_sid = (
                    ace.get("PrincipalSID")
                    or ace.get("principalsid")
                    or ace.get("PrincipalId")
                    or _extract_sid(ace)
                )
                if not principal_sid:
                    continue
                principal_sid = str(principal_sid).strip()

                right_name = ace.get("RightName") or ace.get("rightname") or ace.get("Right") or ""
                if not right_name:
                    continue

                canonical_edge = normalize_edge_type(str(right_name))

                # Special check for DCSync rights on Domain objects
                if node_type == "Domain":
                    rn_lower = str(right_name).lower()
                    if rn_lower in (
                        "dcsync",
                        "getchangesall",
                        "ds-replication-get-changes-all",
                        "allextendedrights",
                    ):
                        canonical_edge = "DCSync"
                    elif rn_lower in ("getchanges", "ds-replication-get-changes"):
                        domain_replication_rights.setdefault(principal_sid, set()).add("getchanges")

                if canonical_edge and canonical_edge in EDGE_TYPES:
                    add_ad_edge(
                        self.graph,
                        source=principal_sid,
                        target=current_id,
                        edge_type=canonical_edge,
                        properties={"is_inherited": ace.get("IsInherited", False)},
                    )

            # If principal has GetChanges + GetChangesAll on Domain, grant DCSync
            for principal_sid, rights in domain_replication_rights.items():
                if "getchanges" in rights and "getchangesall" in rights:
                    add_ad_edge(self.graph, source=principal_sid, target=current_id, edge_type="DCSync")

        # 10. ADCS Escalation Edges
        if node_type == "CertTemplate" and props.get("esc1_vulnerable") is True:
            # ESC1: Enrollee supplies arbitrary SAN, allowing instant compromise of Domain Admins
            domain_sid = props.get("domainsid") or item.get("domainsid")
            if domain_sid:
                add_ad_edge(self.graph, source=current_id, target=f"{domain_sid}-512", edge_type="GenericAll", properties={"esc": "ESC1"})

        if node_type == "EnterpriseCA" and props.get("esc8_vulnerable") is True:
            # ESC8: Relaying machine credentials to CA allows forging machine certs to compromise Domain
            domain_sid = props.get("domainsid") or item.get("domainsid")
            if domain_sid:
                add_ad_edge(self.graph, source=current_id, target=f"{domain_sid}-512", edge_type="AdminTo", properties={"esc": "ESC8"})

    @staticmethod
    def _unpack_results(value: Any) -> list[Any]:
        """Normalize varied BloodHound collection schemas (raw list vs {'Results': [...]})."""
        if isinstance(value, list):
            return value
        if isinstance(value, dict) and "Results" in value and isinstance(value["Results"], list):
            return value["Results"]
        return []

