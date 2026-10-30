"""Synthetic Active Directory BloodHound dataset generator for testing and demonstration."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

DOMAIN_NAME = "CORP.LOCAL"
DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"


def build_synthetic_dataset(include_adcs: bool = False) -> dict[str, dict[str, Any]]:
    """
    Construct a complete synthetic Active Directory environment conforming to BloodHound schema:
    - 1 Domain
    - 2 OUs
    - 2 GPOs
    - 5 Groups
    - 20 Users
    - 10 Computers
    - Optional ADCS Certificate Templates & Enterprise CAs
    - Planted attack path:
      victim_bob -> MemberOf -> Help Desk -> GenericAll -> PIVOT-SRV -> AdminTo -> TARGET-SRV
    """
    domain_obj = {
        "ObjectIdentifier": DOMAIN_SID,
        "Properties": {
            "name": DOMAIN_NAME,
            "domainsid": DOMAIN_SID,
            "highvalue": True,
            "distinguishedname": "DC=corp,DC=local",
            "functionallevel": "2016",
        },
        "Aces": [
            {
                "PrincipalSID": f"{DOMAIN_SID}-512",  # Domain Admins
                "PrincipalType": "Group",
                "RightName": "DCSync",
                "IsInherited": False,
            }
        ],
    }

    ous = [
        {
            "ObjectIdentifier": f"{DOMAIN_SID}-OU01",
            "Properties": {
                "name": "SERVERS@CORP.LOCAL",
                "distinguishedname": "OU=Servers,DC=corp,DC=local",
                "blocksinheritance": False,
            },
            "Aces": [
                {
                    "PrincipalSID": f"{DOMAIN_SID}-512",
                    "PrincipalType": "Group",
                    "RightName": "GenericWrite",
                    "IsInherited": False,
                }
            ],
        },
        {
            "ObjectIdentifier": f"{DOMAIN_SID}-OU02",
            "Properties": {
                "name": "USERS@CORP.LOCAL",
                "distinguishedname": "OU=Users,DC=corp,DC=local",
                "blocksinheritance": False,
            },
            "Aces": [],
        },
    ]

    gpos = [
        {
            "ObjectIdentifier": f"{DOMAIN_SID}-GPO01",
            "Properties": {
                "name": "DEFAULT DOMAIN POLICY@CORP.LOCAL",
                "gpcpath": "\\\\CORP.LOCAL\\sysvol\\corp.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}",
            },
            "Aces": [
                {
                    "PrincipalSID": f"{DOMAIN_SID}-500",  # Administrator
                    "PrincipalType": "User",
                    "RightName": "Owns",
                    "IsInherited": False,
                }
            ],
        },
        {
            "ObjectIdentifier": f"{DOMAIN_SID}-GPO02",
            "Properties": {
                "name": "SERVER HARDENING POLICY@CORP.LOCAL",
                "gpcpath": "\\\\CORP.LOCAL\\sysvol\\corp.local\\Policies\\{6AC1786C-016F-11D2-945F-00C04fB984F9}",
            },
            "Aces": [],
        },
    ]

    # 5 Groups
    groups = [
        {
            "ObjectIdentifier": f"{DOMAIN_SID}-512",
            "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True, "highvalue": True},
            "Members": [{"ObjectIdentifier": f"{DOMAIN_SID}-1201", "ObjectType": "User"}],  # da_alice
            "Aces": [],
        },
        {
            "ObjectIdentifier": f"{DOMAIN_SID}-1101",
            "Properties": {"name": "WORKSTATION ADMINS@CORP.LOCAL", "admincount": False, "highvalue": False},
            "Members": [{"ObjectIdentifier": f"{DOMAIN_SID}-1203", "ObjectType": "User"}],  # user_carol
            "Aces": [],
        },
        {
            "ObjectIdentifier": f"{DOMAIN_SID}-1102",
            "Properties": {"name": "HELP DESK@CORP.LOCAL", "admincount": False, "highvalue": False},
            # victim_bob is a member here!
            "Members": [{"ObjectIdentifier": f"{DOMAIN_SID}-1202", "ObjectType": "User"}],
            "Aces": [
                # Help desk can add members to IT Support
                {
                    "PrincipalSID": f"{DOMAIN_SID}-1102",
                    "PrincipalType": "Group",
                    "RightName": "AddMember",
                    "IsInherited": False,
                }
            ],
        },
        {
            "ObjectIdentifier": f"{DOMAIN_SID}-1103",
            "Properties": {"name": "IT SUPPORT@CORP.LOCAL", "admincount": False, "highvalue": False},
            "Members": [{"ObjectIdentifier": f"{DOMAIN_SID}-1204", "ObjectType": "User"}],  # user_dave
            "Aces": [],
        },
        {
            "ObjectIdentifier": f"{DOMAIN_SID}-1104",
            "Properties": {"name": "ALL EMPLOYEES@CORP.LOCAL", "admincount": False, "highvalue": False},
            "Members": [
                {"ObjectIdentifier": uid, "ObjectType": "User"}
                for _, uid, _ in [
                    ("ADMINISTRATOR", f"{DOMAIN_SID}-500", True),
                    ("DA_ALICE", f"{DOMAIN_SID}-1201", True),
                    ("VICTIM_BOB", f"{DOMAIN_SID}-1202", False),
                    ("USER_CAROL", f"{DOMAIN_SID}-1203", False),
                    ("USER_DAVE", f"{DOMAIN_SID}-1204", False),
                    ("USER_EVE", f"{DOMAIN_SID}-1205", False),
                    ("USER_FRANK", f"{DOMAIN_SID}-1206", False),
                    ("USER_GRACE", f"{DOMAIN_SID}-1207", False),
                    ("USER_HEIDI", f"{DOMAIN_SID}-1208", False),
                    ("USER_IVAN", f"{DOMAIN_SID}-1209", False),
                    ("USER_JUDY", f"{DOMAIN_SID}-1210", False),
                    ("USER_MALLORY", f"{DOMAIN_SID}-1211", False),
                    ("USER_OSCAR", f"{DOMAIN_SID}-1212", False),
                    ("USER_PEGGY", f"{DOMAIN_SID}-1213", False),
                    ("USER_TRENT", f"{DOMAIN_SID}-1214", False),
                    ("USER_VICTOR", f"{DOMAIN_SID}-1215", False),
                    ("USER_WALTER", f"{DOMAIN_SID}-1216", False),
                    ("USER_XAVIER", f"{DOMAIN_SID}-1217", False),
                    ("USER_YVONNE", f"{DOMAIN_SID}-1218", False),
                    ("KRBTGT", f"{DOMAIN_SID}-502", True),
                ]
            ],
            "Aces": [],
        },
    ]

    # 20 Users
    user_specs = [
        ("ADMINISTRATOR", f"{DOMAIN_SID}-500", True),
        ("DA_ALICE", f"{DOMAIN_SID}-1201", True),
        ("VICTIM_BOB", f"{DOMAIN_SID}-1202", False),  # Entry point for planted attack path
        ("USER_CAROL", f"{DOMAIN_SID}-1203", False),
        ("USER_DAVE", f"{DOMAIN_SID}-1204", False),
        ("USER_EVE", f"{DOMAIN_SID}-1205", False),
        ("USER_FRANK", f"{DOMAIN_SID}-1206", False),
        ("USER_GRACE", f"{DOMAIN_SID}-1207", False),
        ("USER_HEIDI", f"{DOMAIN_SID}-1208", False),
        ("USER_IVAN", f"{DOMAIN_SID}-1209", False),
        ("USER_JUDY", f"{DOMAIN_SID}-1210", False),
        ("USER_MALLORY", f"{DOMAIN_SID}-1211", False),
        ("USER_OSCAR", f"{DOMAIN_SID}-1212", False),
        ("USER_PEGGY", f"{DOMAIN_SID}-1213", False),
        ("USER_TRENT", f"{DOMAIN_SID}-1214", False),
        ("USER_VICTOR", f"{DOMAIN_SID}-1215", False),
        ("USER_WALTER", f"{DOMAIN_SID}-1216", False),
        ("USER_XAVIER", f"{DOMAIN_SID}-1217", False),
        ("USER_YVONNE", f"{DOMAIN_SID}-1218", False),
        ("KRBTGT", f"{DOMAIN_SID}-502", True),
    ]

    users = []
    for uname, uid, is_high in user_specs:
        u_aces = []
        delegates = []

        # If user_carol, Help Desk has ForceChangePassword on her
        if uname == "USER_CAROL":
            u_aces.append({
                "PrincipalSID": f"{DOMAIN_SID}-1102",  # Help Desk
                "PrincipalType": "Group",
                "RightName": "ForceChangePassword",
                "IsInherited": False,
            })

        # If user_dave, allowed to delegate to SQL01, has SPN set (kerberoastable)
        extra_props = {}
        if uname == "USER_DAVE":
            delegates.append({"ObjectIdentifier": f"{DOMAIN_SID}-2003"})  # SQL01
            extra_props["hasspn"] = True
            extra_props["serviceprincipalnames"] = ["MSSQLSvc/SQL01.CORP.LOCAL:1433"]

        # If user_eve, AS-REP roastable (DONT_REQ_PREAUTH set)
        if uname == "USER_EVE":
            extra_props["dontreqpreauth"] = True

        users.append({
            "ObjectIdentifier": uid,
            "Properties": {
                "name": f"{uname}@{DOMAIN_NAME}",
                "domainsid": DOMAIN_SID,
                "enabled": True,
                "admincount": is_high,
                "highvalue": is_high,
                "description": f"Account for {uname}",
                **extra_props,
            },
            "Aces": u_aces,
            "AllowedToDelegate": delegates,
        })

    # 10 Computers
    computer_specs = [
        ("DC01", "Domain Controller", True),
        ("FS01", "File Server", False),
        ("SQL01", "Database Server", False),
        ("WEB01", "IIS Server", False),
        ("PIVOT-SRV", "Staging Server", False),   # Step 2 in planted path
        ("TARGET-SRV", "Core App Server", True), # Step 3 in planted path
        ("WS01", "Workstation 1", False),
        ("WS02", "Workstation 2", False),
        ("WS03", "Workstation 3", False),
        ("WS04", "Workstation 4", False),
    ]

    computers = []
    for idx, (cname, desc, is_high) in enumerate(computer_specs, start=1):
        cid = f"{DOMAIN_SID}-{2000 + idx}"
        c_aces = []
        local_admins = []
        sessions = []
        rdp = []
        sql_admins = []
        allowed_act = []
        delegates = []

        # PIVOT-SRV (2005): Help Desk group has GenericAll over it!
        if cname == "PIVOT-SRV":
            c_aces.append({
                "PrincipalSID": f"{DOMAIN_SID}-1102",  # Help Desk group
                "PrincipalType": "Group",
                "RightName": "GenericAll",
                "IsInherited": False,
            })

        # TARGET-SRV (2006): PIVOT-SRV has AdminTo TARGET-SRV!
        # TARGET-SRV also hosts active session of DA_ALICE!
        if cname == "TARGET-SRV":
            local_admins.append({"ObjectIdentifier": f"{DOMAIN_SID}-2005"})  # PIVOT-SRV computer account
            sessions.append({"UserId": f"{DOMAIN_SID}-1201", "ComputerId": cid})  # da_alice

        # DC01: Domain Admins are Local Admin
        if cname == "DC01":
            local_admins.append({"ObjectIdentifier": f"{DOMAIN_SID}-512"})

        # WS01: Workstation Admins can RDP
        if cname == "WS01":
            rdp.append({"ObjectIdentifier": f"{DOMAIN_SID}-1101"})

        # SQL01: USER_DAVE is SQLAdmin, DA_ALICE has WriteDacl
        if cname == "SQL01":
            sql_admins.append({"ObjectIdentifier": f"{DOMAIN_SID}-1204"})
            c_aces.append({
                "PrincipalSID": f"{DOMAIN_SID}-1201",
                "PrincipalType": "User",
                "RightName": "WriteDacl",
                "IsInherited": False,
            })

        # WEB01: DA_ALICE has WriteOwner
        if cname == "WEB01":
            c_aces.append({
                "PrincipalSID": f"{DOMAIN_SID}-1201",
                "PrincipalType": "User",
                "RightName": "WriteOwner",
                "IsInherited": False,
            })

        # FS01: IT SUPPORT is AllowedToAct
        if cname == "FS01":
            allowed_act.append({"ObjectIdentifier": f"{DOMAIN_SID}-1103"})

        computers.append({
            "ObjectIdentifier": cid,
            "Properties": {
                "name": f"{cname}.{DOMAIN_NAME}",
                "domainsid": DOMAIN_SID,
                "enabled": True,
                "operatingsystem": "Windows Server 2022" if "WS" not in cname else "Windows 11 Enterprise",
                "description": desc,
                "highvalue": is_high,
                "unconstraineddelegation": (cname == "DC01"),
            },
            "Aces": c_aces,
            "LocalAdmins": {"Results": local_admins, "Collected": True},
            "Sessions": {"Results": sessions, "Collected": True},
            "RemoteDesktop": {"Results": rdp, "Collected": True},
            "SQLAdmin": {"Results": sql_admins, "Collected": True},
            "AllowedToAct": {"Results": allowed_act, "Collected": True},
            "AllowedToDelegate": delegates,
        })

    # ADCS Certificate Templates (ESC1 & ESC4)
    cert_templates = [
        {
            "ObjectIdentifier": f"{DOMAIN_SID}-CT-ESC1",
            "Properties": {
                "name": "ESC1-USER-CERT@CORP.LOCAL",
                "displayname": "ESC1-User-Cert",
                "domainsid": DOMAIN_SID,
                "highvalue": True,
                "esc1_vulnerable": True,
                "enrollee_supplies_subject": True,
                "client_auth": True,
                "requires_manager_approval": False,
                "ra_signatures": 0,
                "ekus": ["Client Authentication (1.3.6.1.5.5.7.3.2)", "Smart Card Logon (1.3.6.1.4.1.311.20.2.2)"],
            },
            "Aces": [
                {
                    "PrincipalSID": f"{DOMAIN_SID}-1104",  # All Employees
                    "PrincipalType": "Group",
                    "RightName": "ADCSEnroll",
                    "IsInherited": False,
                },
                {
                    "PrincipalSID": f"{DOMAIN_SID}-512",  # Domain Admins
                    "PrincipalType": "Group",
                    "RightName": "GenericAll",
                    "IsInherited": False,
                },
            ],
        },
        {
            "ObjectIdentifier": f"{DOMAIN_SID}-CT-ESC4",
            "Properties": {
                "name": "ESC4-WEB-CERT@CORP.LOCAL",
                "displayname": "ESC4-Web-Cert",
                "domainsid": DOMAIN_SID,
                "highvalue": False,
                "esc4_vulnerable": True,
            },
            "Aces": [
                {
                    "PrincipalSID": f"{DOMAIN_SID}-1102",  # Help Desk
                    "PrincipalType": "Group",
                    "RightName": "ADCSVulnerableTemplate",
                    "IsInherited": False,
                }
            ],
        },
    ]

    # ADCS Enterprise Certificate Authorities (ESC8)
    enterprise_cas = [
        {
            "ObjectIdentifier": f"{DOMAIN_SID}-CA01",
            "Properties": {
                "name": "CORP-CA01@CORP.LOCAL",
                "dnshostname": "FS01.CORP.LOCAL",
                "domainsid": DOMAIN_SID,
                "highvalue": True,
                "esc8_vulnerable": True,
                "web_enrollment_enabled": True,
                "web_enrollment_url": "http://fs01.corp.local/certsrv/",
                "epa_enabled": False,
                "ssl_required": False,
            },
            "Aces": [
                {
                    "PrincipalSID": f"{DOMAIN_SID}-1005",  # TARGET-SRV
                    "PrincipalType": "Computer",
                    "RightName": "ADCSHostRelay",
                    "IsInherited": False,
                }
            ],
        }
    ]

    res = {
        "domains.json": {"data": [domain_obj], "meta": {"type": "domains", "count": 1, "version": 5}},
        "ous.json": {"data": ous, "meta": {"type": "ous", "count": len(ous), "version": 5}},
        "gpos.json": {"data": gpos, "meta": {"type": "gpos", "count": len(gpos), "version": 5}},
        "groups.json": {"data": groups, "meta": {"type": "groups", "count": len(groups), "version": 5}},
        "users.json": {"data": users, "meta": {"type": "users", "count": len(users), "version": 5}},
        "computers.json": {"data": computers, "meta": {"type": "computers", "count": len(computers), "version": 5}},
    }

    if include_adcs:
        res["certtemplates.json"] = {"data": cert_templates, "meta": {"type": "certtemplates", "count": len(cert_templates), "version": 5}}
        res["cas.json"] = {"data": enterprise_cas, "meta": {"type": "cas", "count": len(enterprise_cas), "version": 5}}

    return res


def write_sample_zip(destination_zip: str | Path, include_adcs: bool = False) -> Path:
    """Generate the synthetic dataset and write it as a zip file."""
    dest = Path(destination_zip)
    dest.parent.mkdir(parents=True, exist_ok=True)

    dataset = build_synthetic_dataset(include_adcs=include_adcs)
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for filename, payload in dataset.items():
            zf.writestr(filename, json.dumps(payload, indent=2))

    return dest


def write_sample_adcs_zip(destination_zip: str | Path) -> Path:
    """Generate the synthetic dataset including ADCS PKI objects and write it as a zip file."""
    return write_sample_zip(destination_zip, include_adcs=True)
