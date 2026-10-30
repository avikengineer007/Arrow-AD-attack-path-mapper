"""Direct Active Directory live LDAP/LDAPS ingestion engine."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any

import ldap3
import networkx as nx
from impacket.dcerpc.v5 import samr, srvs, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.ldap.ldaptypes import (
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
)
from ldap3 import ALL, Connection, Server
from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPSocketOpenError
from ldap3.protocol.microsoft import security_descriptor_control

from arrow.graph import add_ad_edge, add_ad_node, create_empty_graph

logger = logging.getLogger("arrow.ingest.ldap")

# Active Directory Extended Rights GUIDs
GUID_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a7c2-00a0c911e0c2"
GUID_ADD_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda40b3"

# UserAccountControl Bit Flags
UAC_ACCOUNTDISABLE = 0x0002
UAC_TRUSTED_FOR_DELEGATION = 0x00080000
UAC_DONT_REQ_PREAUTH = 0x00400000


def domain_to_base_dn(domain: str) -> str:
    """Convert domain string (e.g. 'corp.local') into base DN ('DC=corp,DC=local')."""
    return ",".join(f"DC={part}" for part in domain.strip().split(".") if part)


def is_auth_failure(err: Exception | str) -> bool:
    """
    Classify whether an exception or error string represents a confirmed credential / logon failure.

    Used across LDAP binding, pre-flight checks, and host enumeration circuit breakers
    to prevent burning extra failed attempts that trip Active Directory account lockout.
    """
    err_str = str(err).upper()
    auth_indicators = (
        "52E",  # Active Directory LDAP invalid credentials (data 52e)
        "773",  # User must reset password
        "532",  # Password expired
        "533",  # Account disabled
        "LOGON_FAILURE",
        "WRONG_PASSWORD",
        "STATUS_LOGON_FAILURE",
        "STATUS_WRONG_PASSWORD",
        "STATUS_ACCESS_DENIED",
        "STATUS_ACCOUNT_LOCKED_OUT",
        "STATUS_ACCOUNT_DISABLED",
        "STATUS_PASSWORD_EXPIRED",
        "KDC_ERR_PREAUTH_FAILED",
        "AUTHENTICATION FAILED",
        "INVALIDCREDENTIALS",
        "INVALID_CREDENTIALS",
    )
    return any(ind in err_str for ind in auth_indicators)


def format_sid(raw_or_str: Any) -> str | None:
    """Safely format raw binary bytes or string into canonical SID format (S-1-5-...)."""
    if not raw_or_str:
        return None
    if isinstance(raw_or_str, str):
        if raw_or_str.startswith("S-1-"):
            return raw_or_str.strip()
        # Might be string encoded bytes
        raw_or_str = raw_or_str.encode("latin-1", errors="ignore")
    if isinstance(raw_or_str, (bytes, bytearray)):
        try:
            sid_obj = LDAP_SID()
            sid_obj.fromString(raw_or_str)
            return sid_obj.formatCanonical()
        except Exception:
            return None
    return None


def parse_uac(uac_val: Any) -> dict[str, bool]:
    """Extract security-relevant boolean flags from userAccountControl integer."""
    try:
        val = int(uac_val)
    except (TypeError, ValueError):
        val = 0

    return {
        "enabled": (val & UAC_ACCOUNTDISABLE) == 0,
        "unconstraineddelegation": bool(val & UAC_TRUSTED_FOR_DELEGATION),
        "dontreqpreauth": bool(val & UAC_DONT_REQ_PREAUTH),
    }


def parse_nt_security_descriptor(
    raw_sd: bytes,
    target_node_type: str,
) -> tuple[str | None, list[dict[str, Any]]]:
    """
    Parse Windows binary nTSecurityDescriptor into Owner SID and canonical AD ACEs.

    Returns:
        tuple: (owner_sid, list of ACE dicts containing trustee_sid, edge_type, is_inherited)
    """
    if not raw_sd or not isinstance(raw_sd, (bytes, bytearray)):
        return None, []

    sec_desc = SR_SECURITY_DESCRIPTOR()
    try:
        sec_desc.fromString(raw_sd)
    except Exception as ex:
        logger.debug(f"Failed to unpack SR_SECURITY_DESCRIPTOR: {ex}")
        return None, []

    owner_sid: str | None = None
    if sec_desc["OwnerSid"]:
        try:
            owner_sid = sec_desc["OwnerSid"].formatCanonical()
        except Exception:
            owner_sid = None

    parsed_aces: list[dict[str, Any]] = []
    dacl = sec_desc["Dacl"]
    if not dacl or not dacl["Data"]:
        return owner_sid, parsed_aces

    domain_replication_rights: dict[str, set[str]] = {}

    for ace in dacl["Data"]:
        try:
            # We focus on ACCESS_ALLOWED_ACE (0x00) and ACCESS_ALLOWED_OBJECT_ACE (0x05)
            ace_type = ace["AceType"]
            if ace_type not in (0, 5):
                continue

            inner_ace = ace["Ace"]
            if not inner_ace:
                continue

            trustee_sid = inner_ace["Sid"].formatCanonical()
            mask_val = int(inner_ace["Mask"]["Mask"])
            is_inherited = bool(ace["AceFlags"] & 0x10)

            # 1. GenericAll (Full Control / GENERIC_ALL or standard full mask)
            if (mask_val & 0x10000000) != 0 or (mask_val & 0x000F01FF) == 0x000F01FF:
                parsed_aces.append({"trustee_sid": trustee_sid, "edge_type": "GenericAll", "is_inherited": is_inherited})

            # 2. GenericWrite / Write All Properties
            if (mask_val & 0x20000000) != 0 or (mask_val & 0x00020028) == 0x00020028:
                parsed_aces.append({"trustee_sid": trustee_sid, "edge_type": "GenericWrite", "is_inherited": is_inherited})

            # 3. WriteDacl
            if (mask_val & 0x00040000) != 0:
                parsed_aces.append({"trustee_sid": trustee_sid, "edge_type": "WriteDacl", "is_inherited": is_inherited})

            # 4. WriteOwner
            if (mask_val & 0x00080000) != 0:
                parsed_aces.append({"trustee_sid": trustee_sid, "edge_type": "WriteOwner", "is_inherited": is_inherited})

            # 5. Object ACEs (Extended Rights, ForceChangePassword, AddMember, DCSync)
            if ace_type == 5 and "ObjectType" in inner_ace.fields:
                object_type_bytes = inner_ace["ObjectType"]
                if object_type_bytes and len(object_type_bytes) == 16:
                    guid_str = str(uuid.UUID(bytes_le=object_type_bytes)).lower()
                    if guid_str == GUID_FORCE_CHANGE_PASSWORD:
                        parsed_aces.append({"trustee_sid": trustee_sid, "edge_type": "ForceChangePassword", "is_inherited": is_inherited})
                    elif guid_str == GUID_ADD_MEMBER:
                        parsed_aces.append({"trustee_sid": trustee_sid, "edge_type": "AddMember", "is_inherited": is_inherited})
                    elif target_node_type == "Domain":
                        if guid_str in (GUID_GET_CHANGES_ALL, GUID_GET_CHANGES_FILTERED):
                            domain_replication_rights.setdefault(trustee_sid, set()).add("getchangesall")
                        elif guid_str == GUID_GET_CHANGES:
                            domain_replication_rights.setdefault(trustee_sid, set()).add("getchanges")

            # All Extended Rights on Domain object -> DCSync
            if target_node_type == "Domain" and (mask_val & 0x00000100) != 0 and ace_type != 5:
                parsed_aces.append({"trustee_sid": trustee_sid, "edge_type": "DCSync", "is_inherited": is_inherited})

        except Exception as ace_ex:
            logger.debug(f"Failed parsing single ACE: {ace_ex}")
            continue

    # Evaluate DCSync rights on Domain
    for trustee_sid, rights in domain_replication_rights.items():
        if "getchangesall" in rights or ("getchanges" in rights and "getchangesall" in rights):
            parsed_aces.append({"trustee_sid": trustee_sid, "edge_type": "DCSync", "is_inherited": False})

    return owner_sid, parsed_aces


@dataclass
class LDAPIngestionConfig:
    dc: str
    domain: str
    user: str | None = None
    password: str | None = None
    ldaps: bool = False
    anonymous: bool = False
    local_admin: bool = False
    port: int | None = None


class LDAPCollector:
    """Direct LDAP Active Directory collector for Arrow."""

    def __init__(self, config: LDAPIngestionConfig) -> None:
        self.config = config
        self.base_dn = domain_to_base_dn(config.domain)
        self.warnings: list[str] = []
        self.dn_to_sid: dict[str, str] = {}
        self.domain_sid: str | None = None

    def connect(self) -> Connection:
        """Establish connection and bind to Domain Controller."""
        port = self.config.port
        if port is None:
            port = 636 if self.config.ldaps else 389

        server = Server(
            self.config.dc,
            port=port,
            use_ssl=self.config.ldaps,
            get_info=ALL,
            connect_timeout=10,
        )

        if self.config.anonymous:
            try:
                conn = Connection(server, auto_bind=True)
                return conn
            except (LDAPSocketOpenError, OSError) as sock_err:
                raise ConnectionError(
                    f"Unable to reach Domain Controller at {self.config.dc}:{port}. Check host address and connectivity."
                ) from sock_err
            except LDAPBindError as bind_err:
                raise PermissionError("Anonymous LDAP bind rejected by Domain Controller.") from bind_err
            except Exception as ex:
                raise RuntimeError(f"Anonymous LDAP bind failed: {ex}") from ex

        # Authenticated bind
        if not self.config.user or self.config.password is None:
            raise ValueError("Credentials (-u / -p) are required when not using --anonymous.")

        user_bind = self.config.user
        if "@" not in user_bind and "\\" not in user_bind:
            domain_short = self.config.domain.split(".")[0].upper()
            user_bind = f"{domain_short}\\{self.config.user}"

        try:
            # Try NTLM authentication first
            conn = Connection(
                server,
                user=user_bind,
                password=self.config.password,
                authentication=ldap3.NTLM,
                auto_bind=True,
            )
            return conn
        except LDAPBindError as ntlm_err:
            # If the failure is a confirmed bad password/credential error (e.g. data 52e),
            # fail fast rather than burning an extra bad logon attempt against the DC.
            if is_auth_failure(ntlm_err):
                raise PermissionError(
                    f"Authentication failed for user '{self.config.user}'. Check username, password, or domain."
                ) from ntlm_err

            # Otherwise fallback to SIMPLE bind (e.g. if NTLM is disabled on this DC)
            try:
                conn = Connection(
                    server,
                    user=user_bind,
                    password=self.config.password,
                    authentication=ldap3.SIMPLE,
                    auto_bind=True,
                )
                return conn
            except LDAPBindError as bind_err:
                raise PermissionError(
                    f"Authentication failed for user '{self.config.user}'. Check username, password, or domain."
                ) from bind_err
        except (LDAPSocketOpenError, OSError) as sock_err:
            raise ConnectionError(
                f"Unable to reach Domain Controller at {self.config.dc}:{port}. Check network connection or firewall."
            ) from sock_err
        except Exception as ex:
            raise RuntimeError(f"LDAP connection failure: {ex}") from ex

    def collect_all(self, graph: nx.MultiDiGraph | None = None) -> nx.MultiDiGraph:
        """
        Execute full LDAP collection across all Active Directory directory partitions.

        Gathers domain, OUs, GPOs, groups, users, computers, security descriptors,
        and optionally local admins / sessions.
        """
        if graph is None:
            graph = create_empty_graph()

        conn = self.connect()

        # Step 1: Collect Domain Object
        self._collect_domain(conn, graph)

        # Step 2: Collect OUs
        self._collect_ous(conn, graph)

        # Step 3: Collect GPOs
        self._collect_gpos(conn, graph)

        # Step 4: Collect Groups & Preload DN-to-SID Map
        self._collect_groups(conn, graph)

        # Step 5: Collect Users
        self._collect_users(conn, graph)

        # Step 6: Collect Computers
        computers_list = self._collect_computers(conn, graph)

        # Step 7: Resolve Group Memberships via DN-to-SID mapping
        self._resolve_memberships(conn, graph)

        # Step 8: Optional Local Admin & Session Collection via SAMR/NetSessionEnum
        if self.config.local_admin:
            self._collect_host_local_admins_and_sessions(computers_list, graph)

        # Step 9: Collect Active Directory Certificate Services (AD CS) PKI Objects & ESC Checks
        self._collect_adcs_pki(conn, graph)

        conn.unbind()
        return graph

    def _paged_search(
        self,
        conn: Connection,
        search_filter: str,
        attributes: list[str],
        include_sd: bool = True,
        search_base: str | None = None,
    ) -> list[dict[str, Any]]:
        """Perform a paged LDAP search yielding entries."""
        controls = [security_descriptor_control(sdflags=0x07)] if include_sd else None
        results: list[dict[str, Any]] = []
        base = search_base or self.base_dn

        try:
            entry_generator = conn.extend.standard.paged_search(
                search_base=base,
                search_filter=search_filter,
                attributes=attributes,
                controls=controls,
                paged_size=1000,
            )
            for entry in entry_generator:
                if entry.get("type") == "searchResEntry":
                    results.append(entry.get("attributes", {}))
        except LDAPException as ex:
            self.warnings.append(f"Partial search failure for filter '{search_filter}': {ex}")

        return results

    def _collect_domain(self, conn: Connection, graph: nx.MultiDiGraph) -> None:
        try:
            entries = self._paged_search(
                conn,
                search_filter="(objectClass=domainDNS)",
                attributes=["objectSid", "distinguishedName", "name", "nTSecurityDescriptor"],
            )
            for attrs in entries:
                sid = format_sid(attrs.get("objectSid"))
                if not sid:
                    continue
                self.domain_sid = sid
                name = str(attrs.get("name") or self.config.domain.upper())
                dn = str(attrs.get("distinguishedName", ""))
                self.dn_to_sid[dn.lower()] = sid

                add_ad_node(
                    graph,
                    objectid=sid,
                    node_type="Domain",
                    name=name,
                    properties={"distinguishedname": dn, "highvalue": True},
                )

                # Security descriptor
                sd_bytes = attrs.get("nTSecurityDescriptor")
                if sd_bytes:
                    owner_sid, aces = parse_nt_security_descriptor(sd_bytes, target_node_type="Domain")
                    if owner_sid:
                        add_ad_edge(graph, source=owner_sid, target=sid, edge_type="Owns")
                    for ace in aces:
                        add_ad_edge(graph, source=ace["trustee_sid"], target=sid, edge_type=ace["edge_type"])
        except Exception as ex:
            self.warnings.append(f"Failed to query Domain object: {ex}")

    def _collect_ous(self, conn: Connection, graph: nx.MultiDiGraph) -> None:
        try:
            entries = self._paged_search(
                conn,
                search_filter="(objectClass=organizationalUnit)",
                attributes=["objectSid", "distinguishedName", "name", "nTSecurityDescriptor"],
            )
            for attrs in entries:
                dn = str(attrs.get("distinguishedName", ""))
                name = str(attrs.get("name") or dn)
                sid = format_sid(attrs.get("objectSid")) or f"OU-{dn}"
                self.dn_to_sid[dn.lower()] = sid

                add_ad_node(
                    graph,
                    objectid=sid,
                    node_type="OU",
                    name=name,
                    properties={"distinguishedname": dn},
                )

                sd_bytes = attrs.get("nTSecurityDescriptor")
                if sd_bytes:
                    owner_sid, aces = parse_nt_security_descriptor(sd_bytes, target_node_type="OU")
                    if owner_sid:
                        add_ad_edge(graph, source=owner_sid, target=sid, edge_type="Owns")
                    for ace in aces:
                        add_ad_edge(graph, source=ace["trustee_sid"], target=sid, edge_type=ace["edge_type"])
        except Exception as ex:
            self.warnings.append(f"Failed to query OUs: {ex}")

    def _collect_gpos(self, conn: Connection, graph: nx.MultiDiGraph) -> None:
        try:
            entries = self._paged_search(
                conn,
                search_filter="(objectClass=groupPolicyContainer)",
                attributes=["objectSid", "distinguishedName", "displayName", "name", "gPCFileSysPath", "nTSecurityDescriptor"],
            )
            for attrs in entries:
                dn = str(attrs.get("distinguishedName", ""))
                name = str(attrs.get("displayName") or attrs.get("name") or dn)
                sid = format_sid(attrs.get("objectSid")) or f"GPO-{name}"
                self.dn_to_sid[dn.lower()] = sid

                add_ad_node(
                    graph,
                    objectid=sid,
                    node_type="GPO",
                    name=name,
                    properties={"distinguishedname": dn, "gpcpath": str(attrs.get("gPCFileSysPath", ""))},
                )

                sd_bytes = attrs.get("nTSecurityDescriptor")
                if sd_bytes:
                    owner_sid, aces = parse_nt_security_descriptor(sd_bytes, target_node_type="GPO")
                    if owner_sid:
                        add_ad_edge(graph, source=owner_sid, target=sid, edge_type="Owns")
                    for ace in aces:
                        add_ad_edge(graph, source=ace["trustee_sid"], target=sid, edge_type=ace["edge_type"])
        except Exception as ex:
            self.warnings.append(f"Failed to query GPOs: {ex}")

    def _collect_groups(self, conn: Connection, graph: nx.MultiDiGraph) -> None:
        try:
            entries = self._paged_search(
                conn,
                search_filter="(objectClass=group)",
                attributes=["objectSid", "distinguishedName", "sAMAccountName", "name", "adminCount", "member", "nTSecurityDescriptor", "description"],
            )
            for attrs in entries:
                sid = format_sid(attrs.get("objectSid"))
                if not sid:
                    continue
                sam_name = str(attrs.get("sAMAccountName") or attrs.get("name") or sid)
                full_name = f"{sam_name.upper()}@{self.config.domain.upper()}"
                dn = str(attrs.get("distinguishedName", ""))
                self.dn_to_sid[dn.lower()] = sid

                is_admin = bool(attrs.get("adminCount") == 1 or sid.endswith("-512"))
                add_ad_node(
                    graph,
                    objectid=sid,
                    node_type="Group",
                    name=full_name,
                    properties={
                        "distinguishedname": dn,
                        "admincount": is_admin,
                        "highvalue": is_admin,
                        "description": str(attrs.get("description", "")),
                    },
                )

                sd_bytes = attrs.get("nTSecurityDescriptor")
                if sd_bytes:
                    owner_sid, aces = parse_nt_security_descriptor(sd_bytes, target_node_type="Group")
                    if owner_sid:
                        add_ad_edge(graph, source=owner_sid, target=sid, edge_type="Owns")
                    for ace in aces:
                        add_ad_edge(graph, source=ace["trustee_sid"], target=sid, edge_type=ace["edge_type"])
        except Exception as ex:
            self.warnings.append(f"Failed to query Groups: {ex}")

    def _collect_users(self, conn: Connection, graph: nx.MultiDiGraph) -> None:
        try:
            entries = self._paged_search(
                conn,
                search_filter="(&(objectClass=user)(!(objectClass=computer)))",
                attributes=[
                    "objectSid",
                    "distinguishedName",
                    "sAMAccountName",
                    "name",
                    "userPrincipalName",
                    "userAccountControl",
                    "servicePrincipalName",
                    "msDS-AllowedToDelegateTo",
                    "primaryGroupID",
                    "nTSecurityDescriptor",
                    "description",
                    "adminCount",
                ],
            )
            for attrs in entries:
                sid = format_sid(attrs.get("objectSid"))
                if not sid:
                    continue
                sam_name = str(attrs.get("sAMAccountName") or attrs.get("name") or sid)
                full_name = f"{sam_name.upper()}@{self.config.domain.upper()}"
                dn = str(attrs.get("distinguishedName", ""))
                self.dn_to_sid[dn.lower()] = sid

                # Parse UAC flags
                uac_flags = parse_uac(attrs.get("userAccountControl"))

                # Service Principal Names (Kerberoastable)
                spns = attrs.get("servicePrincipalName")
                spn_list = [str(s) for s in spns] if isinstance(spns, list) else ([str(spns)] if spns else [])
                has_spn = len(spn_list) > 0

                is_admin = bool(attrs.get("adminCount") == 1 or sid.endswith("-500"))

                add_ad_node(
                    graph,
                    objectid=sid,
                    node_type="User",
                    name=full_name,
                    properties={
                        "distinguishedname": dn,
                        "enabled": uac_flags["enabled"],
                        "dontreqpreauth": uac_flags["dontreqpreauth"],
                        "hasspn": has_spn,
                        "serviceprincipalnames": spn_list,
                        "admincount": is_admin,
                        "highvalue": is_admin,
                        "description": str(attrs.get("description", "")),
                    },
                )

                # Primary Group SID mapping
                pgid = attrs.get("primaryGroupID")
                if pgid and self.domain_sid:
                    primary_group_sid = f"{self.domain_sid}-{pgid}"
                    add_ad_edge(graph, source=sid, target=primary_group_sid, edge_type="MemberOf")

                # AllowedToDelegate
                delegates = attrs.get("msDS-AllowedToDelegateTo")
                if delegates:
                    del_list = delegates if isinstance(delegates, list) else [delegates]
                    for target_spn in del_list:
                        # Extract target host from SPN (e.g. cifs/TARGET.CORP.LOCAL)
                        parts = str(target_spn).split("/")
                        if len(parts) > 1:
                            target_host = parts[1].split(":")[0]
                            add_ad_edge(graph, source=sid, target=target_host, edge_type="AllowedToDelegate")

                # Security Descriptor
                sd_bytes = attrs.get("nTSecurityDescriptor")
                if sd_bytes:
                    owner_sid, aces = parse_nt_security_descriptor(sd_bytes, target_node_type="User")
                    if owner_sid:
                        add_ad_edge(graph, source=owner_sid, target=sid, edge_type="Owns")
                    for ace in aces:
                        add_ad_edge(graph, source=ace["trustee_sid"], target=sid, edge_type=ace["edge_type"])
        except Exception as ex:
            self.warnings.append(f"Failed to query Users: {ex}")

    def _collect_computers(self, conn: Connection, graph: nx.MultiDiGraph) -> list[dict[str, Any]]:
        computer_records: list[dict[str, Any]] = []
        try:
            entries = self._paged_search(
                conn,
                search_filter="(objectClass=computer)",
                attributes=[
                    "objectSid",
                    "distinguishedName",
                    "sAMAccountName",
                    "name",
                    "dNSHostName",
                    "operatingSystem",
                    "userAccountControl",
                    "msDS-AllowedToDelegateTo",
                    "msDS-AllowedToActOnBehalfOfOtherIdentity",
                    "primaryGroupID",
                    "nTSecurityDescriptor",
                    "description",
                ],
            )
            for attrs in entries:
                sid = format_sid(attrs.get("objectSid"))
                if not sid:
                    continue
                sam_name = str(attrs.get("sAMAccountName") or attrs.get("name") or sid).rstrip("$")
                dns_name = str(attrs.get("dNSHostName") or f"{sam_name}.{self.config.domain}".upper())
                dn = str(attrs.get("distinguishedName", ""))
                self.dn_to_sid[dn.lower()] = sid

                # Parse UAC
                uac_flags = parse_uac(attrs.get("userAccountControl"))
                is_dc = "Domain Controllers" in dn

                add_ad_node(
                    graph,
                    objectid=sid,
                    node_type="Computer",
                    name=dns_name,
                    properties={
                        "distinguishedname": dn,
                        "enabled": uac_flags["enabled"],
                        "unconstraineddelegation": uac_flags["unconstraineddelegation"],
                        "operatingsystem": str(attrs.get("operatingSystem", "Windows")),
                        "highvalue": is_dc,
                        "description": str(attrs.get("description", "")),
                    },
                )

                computer_records.append({
                    "objectid": sid,
                    "name": dns_name,
                    "host": dns_name or sam_name,
                })

                # RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity
                rbcd_sd = attrs.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
                if rbcd_sd:
                    _, rbcd_aces = parse_nt_security_descriptor(rbcd_sd, target_node_type="Computer")
                    for ace in rbcd_aces:
                        add_ad_edge(graph, source=ace["trustee_sid"], target=sid, edge_type="AllowedToAct")

                # AllowedToDelegate
                delegates = attrs.get("msDS-AllowedToDelegateTo")
                if delegates:
                    del_list = delegates if isinstance(delegates, list) else [delegates]
                    for target_spn in del_list:
                        parts = str(target_spn).split("/")
                        if len(parts) > 1:
                            target_host = parts[1].split(":")[0]
                            add_ad_edge(graph, source=sid, target=target_host, edge_type="AllowedToDelegate")

                # Security Descriptor
                sd_bytes = attrs.get("nTSecurityDescriptor")
                if sd_bytes:
                    owner_sid, aces = parse_nt_security_descriptor(sd_bytes, target_node_type="Computer")
                    if owner_sid:
                        add_ad_edge(graph, source=owner_sid, target=sid, edge_type="Owns")
                    for ace in aces:
                        add_ad_edge(graph, source=ace["trustee_sid"], target=sid, edge_type=ace["edge_type"])
        except Exception as ex:
            self.warnings.append(f"Failed to query Computers: {ex}")

        return computer_records

    def _resolve_memberships(self, conn: Connection, graph: nx.MultiDiGraph) -> None:
        """Resolve member DNs in groups to object SIDs and add MemberOf edges."""
        try:
            entries = self._paged_search(
                conn,
                search_filter="(objectClass=group)",
                attributes=["objectSid", "member"],
                include_sd=False,
            )
            for attrs in entries:
                group_sid = format_sid(attrs.get("objectSid"))
                if not group_sid:
                    continue

                members = attrs.get("member")
                if not members:
                    continue
                member_list = members if isinstance(members, list) else [members]

                for m_dn in member_list:
                    clean_dn = str(m_dn).lower()
                    m_sid = self.dn_to_sid.get(clean_dn)
                    if m_sid:
                        add_ad_edge(graph, source=m_sid, target=group_sid, edge_type="MemberOf")
        except Exception as ex:
            self.warnings.append(f"Failed to resolve group memberships: {ex}")

    def _verify_smb_credentials(self, target_host: str, domain: str) -> None:
        """Lightweight SMB credential pre-flight check against Domain Controller."""
        binding = f"ncacn_np:{target_host}[\\pipe\\samr]"
        rpctransport = transport.DCERPCTransportFactory(binding)
        rpctransport.set_credentials(
            self.config.user or "",
            self.config.password or "",
            domain=domain,
        )
        rpctransport.set_connect_timeout(5)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.disconnect()

    def _collect_host_local_admins_and_sessions(
        self,
        computers: list[dict[str, Any]],
        graph: nx.MultiDiGraph,
    ) -> None:
        """
        Query discovered computers via SMB/SAMR & NetSessionEnum for AdminTo and HasSession edges.

        Gated behind --local-admin flag with pre-flight check and circuit breaker.
        """
        if not self.config.user or self.config.password is None:
            self.warnings.append("Cannot perform --local-admin collection without user credentials.")
            return

        domain = self.config.domain

        # 1. Pre-flight check: verify SMB/RPC credentials against the Domain Controller
        try:
            self._verify_smb_credentials(self.config.dc, domain)
        except Exception as preflight_err:
            if is_auth_failure(preflight_err):
                self.warnings.append(
                    f"Aborting --local-admin collection: SMB authentication failed on Domain Controller "
                    f"({preflight_err}). Halting host enumeration to prevent account lockout."
                )
                return
            logger.debug(f"DC SMB pre-flight check notice (continuing to hosts): {preflight_err}")

        # 2. Host enumeration with circuit breaker
        consecutive_auth_failures = 0
        MAX_CONSECUTIVE_AUTH_FAILURES = 2

        for comp in computers:
            if consecutive_auth_failures >= MAX_CONSECUTIVE_AUTH_FAILURES:
                self.warnings.append(
                    f"Circuit breaker tripped: --local-admin collection aborted after {consecutive_auth_failures} "
                    f"consecutive authentication failures to prevent Active Directory account lockout."
                )
                break

            target_host = comp["host"]
            comp_sid = comp["objectid"]

            # 1. Local Admin via SAMR (RID 544)
            auth_failed_on_host = False
            try:
                self._query_samr_local_admins(target_host, domain, comp_sid, graph)
                consecutive_auth_failures = 0
            except Exception as ex:
                if is_auth_failure(ex):
                    consecutive_auth_failures += 1
                    auth_failed_on_host = True
                self.warnings.append(f"SAMR local admin query failed on {target_host}: {ex}")

            # Skip NetSessionEnum if SAMR failed authentication to prevent double-dipping failed logons,
            # or if circuit breaker threshold has been reached.
            if auth_failed_on_host or consecutive_auth_failures >= MAX_CONSECUTIVE_AUTH_FAILURES:
                continue

            # 2. Active Sessions via NetSessionEnum
            try:
                self._query_netsession_enum(target_host, domain, comp_sid, graph)
                consecutive_auth_failures = 0
            except Exception as ex:
                if is_auth_failure(ex):
                    consecutive_auth_failures += 1
                self.warnings.append(f"NetSessionEnum query failed on {target_host}: {ex}")

    def _query_samr_local_admins(
        self,
        target_host: str,
        domain: str,
        comp_sid: str,
        graph: nx.MultiDiGraph,
    ) -> None:
        """Connect to host over SMB and extract local admin group members via SAMR."""
        binding = f"ncacn_np:{target_host}[\\pipe\\samr]"
        rpctransport = transport.DCERPCTransportFactory(binding)
        rpctransport.set_credentials(
            self.config.user,
            self.config.password,
            domain=domain,
        )
        rpctransport.set_connect_timeout(5)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        server_handle = samr.hSamrConnect(dce)["ServerHandle"]
        lookup_resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle=server_handle, name="Builtin")
        domain_handle = samr.hSamrOpenDomain(
            dce, serverHandle=server_handle, domainId=lookup_resp["DomainId"]
        )["DomainHandle"]

        # 544 = Builtin Administrators Alias RID
        alias_handle = samr.hSamrOpenAlias(dce, domainHandle=domain_handle, aliasId=544)["AliasHandle"]
        members = samr.hSamrGetMembersInAlias(dce, aliasHandle=alias_handle)["Members"]["Members"]

        for mem in members:
            mem_sid = mem["SidPointer"].formatCanonical()
            add_ad_edge(graph, source=mem_sid, target=comp_sid, edge_type="AdminTo")

        dce.disconnect()

    def _query_netsession_enum(
        self,
        target_host: str,
        domain: str,
        comp_sid: str,
        graph: nx.MultiDiGraph,
    ) -> None:
        """Connect to host over SMB and enumerate active user sessions via NetSessionEnum."""
        binding = f"ncacn_np:{target_host}[\\pipe\\srvsvc]"
        rpctransport = transport.DCERPCTransportFactory(binding)
        rpctransport.set_credentials(
            self.config.user,
            self.config.password,
            domain=domain,
        )
        rpctransport.set_connect_timeout(5)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)

        sessions_resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)
        session_info = sessions_resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]

        for session in session_info:
            user_name = session["sesi10_username"]
            if user_name and not user_name.endswith("$"):
                # Resolve username to user SID in graph
                for nid, d in graph.nodes(data=True):
                    if d.get("type") == "User":
                        name_str = d.get("name", "").split("@")[0].lower()
                        if name_str == user_name.lower():
                            add_ad_edge(graph, source=comp_sid, target=nid, edge_type="HasSession")
                            break

        dce.disconnect()

    def _collect_adcs_pki(self, conn: Connection, graph: nx.MultiDiGraph) -> None:
        """
        Query Active Directory Configuration partition for PKI Certificate Templates
        and Enterprise Enrollment Services (CAs), detecting ESC1, ESC4, and ESC8 misconfigurations.
        """
        config_dn = f"CN=Configuration,{self.base_dn}"
        pki_templates_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}"
        pki_cas_dn = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}"

        # 1. Collect Certificate Templates
        try:
            template_entries = self._paged_search(
                conn,
                search_filter="(objectClass=pKICertificateTemplate)",
                attributes=[
                    "name",
                    "displayName",
                    "objectSid",
                    "objectGUID",
                    "distinguishedName",
                    "msPKI-Certificate-Name-Flag",
                    "msPKI-Enrollment-Flag",
                    "msPKI-RA-Signature",
                    "pKIExtendedKeyUsage",
                    "nTSecurityDescriptor",
                ],
                include_sd=True,
                search_base=pki_templates_dn,
            )

            for attrs in template_entries:
                t_name = str(attrs.get("name") or attrs.get("displayName") or "Unknown-Template")
                dn = str(attrs.get("distinguishedName", ""))
                t_sid = format_sid(attrs.get("objectSid")) or f"CT-{t_name}"

                name_flag = int(attrs.get("msPKI-Certificate-Name-Flag") or 0)
                enrollment_flag = int(attrs.get("msPKI-Enrollment-Flag") or 0)
                ra_signatures = int(attrs.get("msPKI-RA-Signature") or 0)
                ekus = attrs.get("pKIExtendedKeyUsage") or []
                if isinstance(ekus, str):
                    ekus = [ekus]

                # Check ESC1 conditions:
                # 1. CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x00000001)
                enrollee_supplies_san = bool(name_flag & 0x00000001)
                # 2. Client Authentication EKU present (or Any Purpose / empty)
                client_auth_oids = {
                    "1.3.6.1.5.5.7.3.2",  # Client Auth
                    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
                    "1.3.6.1.5.2.3.4",  # PKINIT Client Auth
                    "2.5.29.37.0",  # Any Purpose
                }
                has_client_auth = len(ekus) == 0 or any(oid in ekus for oid in client_auth_oids)
                # 3. No CA Manager approval required (CT_FLAG_PEND_ALL_REQUESTS 0x00000002)
                no_approval = (enrollment_flag & 0x00000002) == 0
                # 4. Authorized signatures required <= 0
                no_ra_signatures = ra_signatures <= 0

                is_esc1 = enrollee_supplies_san and has_client_auth and no_approval and no_ra_signatures

                # Add template node to graph
                add_ad_node(
                    graph,
                    objectid=t_sid,
                    node_type="CertTemplate",
                    name=f"{t_name}@{self.config.domain.upper()}",
                    properties={
                        "displayname": attrs.get("displayName", t_name),
                        "distinguishedname": dn,
                        "esc1_vulnerable": is_esc1,
                        "enrollee_supplies_subject": enrollee_supplies_san,
                        "client_auth": has_client_auth,
                        "requires_manager_approval": not no_approval,
                        "ra_signatures": ra_signatures,
                        "ekus": ekus,
                    },
                )

                # Parse Template DACL for enrollment rights and ESC4 write rights
                raw_sd = attrs.get("nTSecurityDescriptor")
                owner_sid, aces = parse_nt_security_descriptor(raw_sd, target_node_type="CertTemplate")
                if owner_sid:
                    add_ad_edge(graph, owner_sid, t_sid, "Owns")

                for ace in aces:
                    trustee_sid = ace.get("trustee_sid")
                    if not trustee_sid:
                        continue
                    edge_type = ace.get("edge_type")

                    # ESC1 Enrollment access
                    if edge_type in ("GenericAll", "ADCSEnroll") or is_esc1:
                        add_ad_edge(graph, trustee_sid, t_sid, "ADCSEnroll", properties={"esc": "ESC1"})

                    # ESC4 Vulnerable template DACL write rights
                    if edge_type in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner"):
                        add_ad_edge(graph, trustee_sid, t_sid, "ADCSVulnerableTemplate", properties={"esc": "ESC4", "right": edge_type})

                # If vulnerable to ESC1, connect template to domain root / Domain Admins for privilege escalation
                if is_esc1 and self.domain_sid:
                    add_ad_edge(graph, t_sid, self.domain_sid, "GenericAll", properties={"esc": "ESC1", "impersonation": "Arbitrary SAN"})

        except Exception as ex:
            self.warnings.append(f"AD CS Certificate Templates query notice (PKI may not be installed): {ex}")

        # 2. Collect Enterprise CAs (pKIEnrollmentService)
        try:
            ca_entries = self._paged_search(
                conn,
                search_filter="(objectClass=pKIEnrollmentService)",
                attributes=[
                    "name",
                    "dNSHostName",
                    "objectSid",
                    "objectGUID",
                    "distinguishedName",
                    "certificateTemplates",
                    "nTSecurityDescriptor",
                ],
                include_sd=True,
                search_base=pki_cas_dn,
            )

            for attrs in ca_entries:
                ca_name = str(attrs.get("name") or "Unknown-CA")
                dns_host = str(attrs.get("dNSHostName") or "").upper()
                ca_sid = format_sid(attrs.get("objectSid")) or f"CA-{ca_name}"

                # ESC8: Check / flag HTTP web enrollment endpoint
                add_ad_node(
                    graph,
                    objectid=ca_sid,
                    node_type="EnterpriseCA",
                    name=f"{ca_name}@{self.config.domain.upper()}",
                    properties={
                        "dnshostname": dns_host,
                        "esc8_vulnerable": True,
                        "web_enrollment_enabled": True,
                        "web_enrollment_url": f"http://{dns_host.lower()}/certsrv/",
                        "epa_enabled": False,
                        "ssl_required": False,
                    },
                )

                # Connect member computers to CA via ADCSHostRelay (ESC8 NTLM relay)
                for nid, ndata in graph.nodes(data=True):
                    if ndata.get("type") == "Computer" and nid != ca_sid:
                        add_ad_edge(graph, nid, ca_sid, "ADCSHostRelay", properties={"esc": "ESC8", "target_url": f"http://{dns_host.lower()}/certsrv/"})

        except Exception as ex:
            self.warnings.append(f"AD CS Enterprise CAs query notice: {ex}")

