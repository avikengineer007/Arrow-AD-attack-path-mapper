"""Unit tests for arrow/ingest/ldap.py."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest
from impacket.ldap.ldaptypes import (
    ACE,
    ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_OBJECT_ACE,
    ACCESS_MASK,
    ACL,
    LDAP_SID,
    SR_SECURITY_DESCRIPTOR,
)

from arrow.graph import create_empty_graph
from arrow.ingest.ldap import (
    GUID_ADD_MEMBER,
    GUID_FORCE_CHANGE_PASSWORD,
    GUID_GET_CHANGES,
    GUID_GET_CHANGES_ALL,
    LDAPCollector,
    LDAPIngestionConfig,
    domain_to_base_dn,
    format_sid,
    parse_nt_security_descriptor,
    parse_uac,
)


def test_domain_to_base_dn():
    assert domain_to_base_dn("corp.local") == "DC=corp,DC=local"
    assert domain_to_base_dn("sub.domain.corp.com") == "DC=sub,DC=domain,DC=corp,DC=com"


def test_format_sid():
    raw_sid_str = "S-1-5-21-123456789-123456789-123456789-500"
    sid_obj = LDAP_SID()
    sid_obj.fromCanonical(raw_sid_str)
    raw_bytes = sid_obj.getData()

    # From raw bytes
    assert format_sid(raw_bytes) == raw_sid_str
    # From canonical string
    assert format_sid(raw_sid_str) == raw_sid_str
    # From None or empty
    assert format_sid(None) is None
    assert format_sid("") is None


def test_parse_uac():
    # Normal enabled account
    res1 = parse_uac(512)
    assert res1["enabled"] is True
    assert res1["unconstraineddelegation"] is False
    assert res1["dontreqpreauth"] is False

    # Disabled account
    res2 = parse_uac(514)  # 512 + 2
    assert res2["enabled"] is False

    # AS-REP roastable (DONT_REQ_PREAUTH = 0x400000 = 4194304)
    res3 = parse_uac(4194816)  # 512 + 4194304
    assert res3["dontreqpreauth"] is True

    # Unconstrained delegation (TRUSTED_FOR_DELEGATION = 0x80000 = 524288)
    res4 = parse_uac(524800)  # 512 + 524288
    assert res4["unconstraineddelegation"] is True


def test_parse_nt_security_descriptor_empty():
    owner, aces = parse_nt_security_descriptor(b"", "User")
    assert owner is None
    assert aces == []


def test_parse_nt_security_descriptor_full():
    """Build a synthetic binary security descriptor with Owner, GenericAll, and Object ACEs."""
    # Set Owner SID
    owner_sid = LDAP_SID()
    owner_sid.fromCanonical("S-1-5-21-1111-2222-3333-500")

    # 1. Standard ACCESS_ALLOWED_ACE with GenericAll mask
    inner1 = ACCESS_ALLOWED_ACE()
    mask1 = ACCESS_MASK()
    mask1["Mask"] = 0x10000000  # GENERIC_ALL
    inner1["Mask"] = mask1
    trustee1 = LDAP_SID()
    trustee1.fromCanonical("S-1-5-21-1111-2222-3333-1101")
    inner1["Sid"] = trustee1

    ace1 = ACE()
    ace1["AceType"] = 0
    ace1["AceFlags"] = 0
    ace1["Ace"] = inner1

    # 2. Standard ACCESS_ALLOWED_ACE with WriteDacl mask
    inner2 = ACCESS_ALLOWED_ACE()
    mask2 = ACCESS_MASK()
    mask2["Mask"] = 0x00040000  # WRITE_DACL
    inner2["Mask"] = mask2
    trustee2 = LDAP_SID()
    trustee2.fromCanonical("S-1-5-21-1111-2222-3333-1102")
    inner2["Sid"] = trustee2

    ace2 = ACE()
    ace2["AceType"] = 0
    ace2["AceFlags"] = 0
    ace2["Ace"] = inner2

    # 3. Object ACE for ForceChangePassword
    inner3 = ACCESS_ALLOWED_OBJECT_ACE()
    mask3 = ACCESS_MASK()
    mask3["Mask"] = 0x00000100  # RIGHT_DS_CONTROL_ACCESS
    inner3["Mask"] = mask3
    inner3["Flags"] = 1  # ACE_OBJECT_TYPE_PRESENT
    inner3["ObjectType"] = uuid.UUID(GUID_FORCE_CHANGE_PASSWORD).bytes_le
    inner3["InheritedObjectType"] = b""
    trustee3 = LDAP_SID()
    trustee3.fromCanonical("S-1-5-21-1111-2222-3333-1103")
    inner3["Sid"] = trustee3

    ace3 = ACE()
    ace3["AceType"] = 5
    ace3["AceFlags"] = 0
    ace3["Ace"] = inner3

    # Set DACL with ACEs
    dacl = ACL()
    dacl["AclRevision"] = 2
    dacl["Sbz1"] = 0
    dacl["Sbz2"] = 0
    dacl.aces = [ace1, ace2, ace3]

    sd = SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"] = b"\x00"
    sd["Control"] = 0x8004
    sd["OwnerSid"] = owner_sid
    sd["GroupSid"] = b""
    sd["Sacl"] = b""
    sd["Dacl"] = dacl

    raw_bytes = sd.getData()
    parsed_owner, parsed_aces = parse_nt_security_descriptor(raw_bytes, target_node_type="User")

    assert parsed_owner == "S-1-5-21-1111-2222-3333-500"
    edge_types = [a["edge_type"] for a in parsed_aces]
    assert "GenericAll" in edge_types
    assert "WriteDacl" in edge_types
    assert "ForceChangePassword" in edge_types


def test_ldap_collector_auth_validation():
    cfg = LDAPIngestionConfig(
        dc="127.0.0.1",
        domain="corp.local",
        user=None,
        password=None,
        anonymous=False,
    )
    collector = LDAPCollector(cfg)
    with pytest.raises(ValueError, match="Credentials"):
        collector.connect()


def test_ldap_collector_unreachable_dc():
    cfg = LDAPIngestionConfig(
        dc="127.0.0.1",
        port=59999,  # Port guaranteed closed locally -> immediate failure without socket timeout
        domain="corp.local",
        anonymous=True,
    )
    collector = LDAPCollector(cfg)
    with pytest.raises(ConnectionError, match="Unable to reach Domain Controller"):
        collector.connect()


def test_adcs_pki_collection_search_bases():
    cfg = LDAPIngestionConfig(
        dc="127.0.0.1",
        domain="corp.local",
        user="testuser",
        password="password",
    )
    collector = LDAPCollector(cfg)
    collector.base_dn = "DC=corp,DC=local"
    collector.domain_sid = "S-1-5-21-1111-2222-3333"

    mock_conn = MagicMock()
    captured_bases = []

    def mock_paged_search(conn, search_filter, attributes, include_sd=True, search_base=None):
        captured_bases.append(search_base)
        return []

    collector._paged_search = mock_paged_search
    g = create_empty_graph()
    collector._collect_adcs_pki(mock_conn, g)

    expected_templates_base = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
    expected_cas_base = "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"

    assert expected_templates_base in captured_bases
    assert expected_cas_base in captured_bases


def test_is_auth_failure_classification():
    from arrow.ingest.ldap import is_auth_failure

    # Positive matches (Active Directory LDAP and SMB errors)
    assert is_auth_failure("LDAPBindError: invalid credentials, data 52e")
    assert is_auth_failure("DCERPCException: STATUS_LOGON_FAILURE")
    assert is_auth_failure("DCERPCException: STATUS_ACCESS_DENIED")
    assert is_auth_failure("Account locked out: STATUS_ACCOUNT_LOCKED_OUT")
    assert is_auth_failure("Kerberos error: KDC_ERR_PREAUTH_FAILED")
    assert is_auth_failure("Authentication failed for user admin")

    # Negative matches (network / socket errors)
    assert not is_auth_failure("Connection timed out on TCP 445")
    assert not is_auth_failure("ConnectionResetError: [Errno 104] Connection reset by peer")
    assert not is_auth_failure("Name or service not known")


def test_dual_bind_fast_fails_on_confirmed_bad_password():
    from ldap3.core.exceptions import LDAPBindError

    cfg = LDAPIngestionConfig(
        dc="127.0.0.1",
        domain="corp.local",
        user="testuser",
        password="badpassword",
    )
    collector = LDAPCollector(cfg)

    with patch("arrow.ingest.ldap.Server"), \
         patch("arrow.ingest.ldap.Connection") as mock_conn:
        # NTLM bind raises bad credentials error with data 52e
        mock_conn.side_effect = LDAPBindError("result: 49 - invalidCredentials, data 52e, v4563")

        with pytest.raises(PermissionError, match="Authentication failed"):
            collector.connect()

        # Assert only 1 bind attempt was made (NTLM) and did NOT fall back to burn attempt #2
        assert mock_conn.call_count == 1


def test_circuit_breaker_halts_local_admin_enumeration():
    cfg = LDAPIngestionConfig(
        dc="192.168.1.10",
        domain="corp.local",
        user="testuser",
        password="password",
        local_admin=True,
    )
    collector = LDAPCollector(cfg)
    g = create_empty_graph()

    # Pre-flight succeeds
    collector._verify_smb_credentials = MagicMock()

    # Mock 10 computers in the domain
    computers = [{"host": f"HOST{i}.corp.local", "objectid": f"S-COMP-{i}"} for i in range(10)]

    # Mock SAMR query to raise STATUS_LOGON_FAILURE
    samr_mock = MagicMock(side_effect=Exception("DCERPCException: STATUS_LOGON_FAILURE"))
    collector._query_samr_local_admins = samr_mock
    collector._query_netsession_enum = MagicMock()

    collector._collect_host_local_admins_and_sessions(computers, g)

    # Circuit breaker threshold is 2: should stop after 2 consecutive failures, NOT querying all 10 hosts!
    assert samr_mock.call_count == 2
    assert any("Circuit breaker tripped" in w for w in collector.warnings)
    assert any("account lockout" in w for w in collector.warnings)


def test_preflight_smb_check_aborts_before_loop():
    cfg = LDAPIngestionConfig(
        dc="192.168.1.10",
        domain="corp.local",
        user="testuser",
        password="password",
        local_admin=True,
    )
    collector = LDAPCollector(cfg)
    g = create_empty_graph()

    # Pre-flight fails with authentication failure
    collector._verify_smb_credentials = MagicMock(
        side_effect=Exception("STATUS_LOGON_FAILURE: The user name or password is incorrect")
    )

    samr_mock = MagicMock()
    collector._query_samr_local_admins = samr_mock
    computers = [{"host": f"HOST{i}.corp.local", "objectid": f"S-COMP-{i}"} for i in range(10)]

    collector._collect_host_local_admins_and_sessions(computers, g)

    # Did not touch any host in computers
    assert samr_mock.call_count == 0
    assert any("Aborting --local-admin collection: SMB authentication failed" in w for w in collector.warnings)
