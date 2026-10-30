"""
Narrative attack-path explanation and MITRE ATT&CK mapping for Arrow.

Translates graph traversal paths into human-readable, attacker-reasoning
narratives with concrete exploitation mechanics and MITRE ATT&CK classifications.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import re
from typing import Any

from arrow.graph import EDGE_TYPES


@dataclass
class EdgeExplanation:
    """Detailed explanation and MITRE ATT&CK mapping for an edge type."""

    edge_type: str
    description: str
    technique: str
    mitre_id: str
    mitre_name: str
    noise_score: float


# Exhaustive explanation dictionary for all 15 edge types in the schema
EDGE_EXPLANATIONS: dict[str, EdgeExplanation] = {
    "MemberOf": EdgeExplanation(
        edge_type="MemberOf",
        description=(
            "Principal is a direct or nested member of the target group, inheriting "
            "all permissions, privileges, and access tokens granted to the group."
        ),
        technique=(
            "Inherit group security token and privileges without generating alerts; "
            "use LDAP or token groups enumeration to verify transitive access."
        ),
        mitre_id="T1069.002",
        mitre_name="Permission Groups Discovery: Domain Groups",
        noise_score=1.0,
    ),
    "AdminTo": EdgeExplanation(
        edge_type="AdminTo",
        description=(
            "Principal has local administrative rights on the target computer (member of "
            "the local Administrators group)."
        ),
        technique=(
            "Authenticate over SMB/RPC or WinRM with local administrative privileges; "
            "execute remote code via service installation or WMI/WinRM to pivot."
        ),
        mitre_id="T1021.002",
        mitre_name="Remote Services: SMB/Windows Admin Shares",
        noise_score=5.0,
    ),
    "HasSession": EdgeExplanation(
        edge_type="HasSession",
        description=(
            "Target privileged user holds an active or disconnected logon session on the computer."
        ),
        technique=(
            "Access LSASS process memory or token impersonation tables as SYSTEM/Admin "
            "to extract plaintext passwords, Kerberos TGTs, or NTLM hashes."
        ),
        mitre_id="T1003.001",
        mitre_name="OS Credential Dumping: LSASS Memory",
        noise_score=8.0,
    ),
    "GenericAll": EdgeExplanation(
        edge_type="GenericAll",
        description=(
            "Principal has full control permissions over the target object, including rights "
            "to read/write all attributes and modify object security descriptors."
        ),
        technique=(
            "If target is a user: reset password or configure shadow credentials; "
            "if target is a group: add controlled accounts; if target is a computer: configure RBCD."
        ),
        mitre_id="T1222.001",
        mitre_name="File and Directory Permissions Modification: Windows DACL",
        noise_score=1.0,
    ),
    "GenericWrite": EdgeExplanation(
        edge_type="GenericWrite",
        description=(
            "Principal has write access to all non-restricted attributes on the target object."
        ),
        technique=(
            "Modify sensitive attributes such as scriptPath, userAccountControl, "
            "servicePrincipalName, or msDS-AllowedToActOnBehalfOfOtherIdentity to hijack execution."
        ),
        mitre_id="T1098",
        mitre_name="Account Manipulation",
        noise_score=1.0,
    ),
    "WriteDacl": EdgeExplanation(
        edge_type="WriteDacl",
        description=(
            "Principal has permission to modify the Discretionary Access Control List (DACL) "
            "of the target object."
        ),
        technique=(
            "Add an Access Control Entry (ACE) granting yourself GenericAll or specific elevated "
            "rights over the target object via LDAP DACL modification."
        ),
        mitre_id="T1222.001",
        mitre_name="File and Directory Permissions Modification: Windows DACL",
        noise_score=1.0,
    ),
    "WriteOwner": EdgeExplanation(
        edge_type="WriteOwner",
        description=(
            "Principal has permission to take ownership of the target Active Directory object."
        ),
        technique=(
            "Take ownership of the object, which inherently grants the right to rewrite the DACL, "
            "then grant yourself GenericAll permissions."
        ),
        mitre_id="T1098.002",
        mitre_name="Account Manipulation: Additional Cloud Credentials / Object Ownership",
        noise_score=1.0,
    ),
    "ForceChangePassword": EdgeExplanation(
        edge_type="ForceChangePassword",
        description=(
            "Principal has permission to force-reset the target user's password without "
            "knowing the existing password."
        ),
        technique=(
            "Reset the user password via LDAP or SAMR password change protocols and logon "
            "as the compromised user."
        ),
        mitre_id="T1098",
        mitre_name="Account Manipulation",
        noise_score=2.0,
    ),
    "AddMember": EdgeExplanation(
        edge_type="AddMember",
        description=(
            "Principal has permission to add new members directly to the target security group."
        ),
        technique=(
            "Add an attacker-controlled user or computer account to the target privileged group "
            "via LDAP modification to inherit all group rights."
        ),
        mitre_id="T1098.001",
        mitre_name="Account Manipulation: Additional Local or Domain Groups",
        noise_score=2.0,
    ),
    "Owns": EdgeExplanation(
        edge_type="Owns",
        description=(
            "Principal is the explicit owner of the target Active Directory object."
        ),
        technique=(
            "As owner, exercise implicit rights to modify the object's DACL to grant yourself "
            "full control (GenericAll)."
        ),
        mitre_id="T1078.002",
        mitre_name="Valid Accounts: Domain Accounts",
        noise_score=1.0,
    ),
    "CanRDP": EdgeExplanation(
        edge_type="CanRDP",
        description=(
            "Principal is authorized to establish an interactive Remote Desktop Protocol (RDP) "
            "session on the target computer."
        ),
        technique=(
            "Establish an interactive GUI session over TCP 3389 to execute commands or hijack "
            "disconnected privileged user sessions."
        ),
        mitre_id="T1021.001",
        mitre_name="Remote Services: Remote Desktop Protocol",
        noise_score=6.0,
    ),
    "AllowedToDelegate": EdgeExplanation(
        edge_type="AllowedToDelegate",
        description=(
            "Principal account is configured for Kerberos Constrained Delegation with Protocol "
            "Transition (S4U) to designated services on the target."
        ),
        technique=(
            "Request a Kerberos service ticket impersonating any high-privilege domain user via "
            "S4U2self, then use S4U2proxy to obtain a forwarded ticket for the target service."
        ),
        mitre_id="T1550.003",
        mitre_name="Use Alternate Authentication Material: Pass the Ticket",
        noise_score=1.5,
    ),
    "AllowedToAct": EdgeExplanation(
        edge_type="AllowedToAct",
        description=(
            "Target computer has msDS-AllowedToActOnBehalfOfOtherIdentity configured allowing "
            "the principal to impersonate users to it (Resource-Based Constrained Delegation)."
        ),
        technique=(
            "Abuse RBCD: request a service ticket via S4U2self and S4U2proxy impersonating an "
            "enterprise administrator to services on the target host."
        ),
        mitre_id="T1550.003",
        mitre_name="Use Alternate Authentication Material: Pass the Ticket",
        noise_score=1.5,
    ),
    "DCSync": EdgeExplanation(
        edge_type="DCSync",
        description=(
            "Principal possesses directory replication rights (DS-Replication-Get-Changes and "
            "DS-Replication-Get-Changes-All) on the domain object."
        ),
        technique=(
            "Simulate a Domain Controller using the MS-DRSR directory replication service to pull "
            "password hashes (including KRBTGT and Administrator) directly from the DC."
        ),
        mitre_id="T1003.006",
        mitre_name="OS Credential Dumping: DCSync",
        noise_score=3.0,
    ),
    "SQLAdmin": EdgeExplanation(
        edge_type="SQLAdmin",
        description=(
            "Principal has sysadmin administrative privileges on the target Microsoft SQL Server instance."
        ),
        technique=(
            "Authenticate over TDS (TCP 1433) with sysadmin role, enable and execute xp_cmdshell "
            "or OLE automation procedures to execute commands as the SQL service account."
        ),
        mitre_id="T1078.002",
        mitre_name="Valid Accounts: Domain Accounts",
        noise_score=4.0,
    ),
    "ADCSEnroll": EdgeExplanation(
        edge_type="ADCSEnroll",
        description=(
            "Principal has enrollment rights on an Active Directory Certificate Services (AD CS) "
            "template configured with Client Authentication and requester-supplied Subject Alternative Name (ESC1)."
        ),
        technique=(
            "Enroll in the certificate template supplying an arbitrary privileged Subject Alternative Name "
            "(e.g. Domain Administrator), then authenticate using Kerberos PKINIT to obtain the victim's TGT."
        ),
        mitre_id="T1649",
        mitre_name="Steal or Forge Authentication Certificates",
        noise_score=1.5,
    ),
    "ADCSVulnerableTemplate": EdgeExplanation(
        edge_type="ADCSVulnerableTemplate",
        description=(
            "Principal has write access or DACL modification permissions (GenericAll/WriteDacl/GenericWrite) "
            "over a published Active Directory certificate template (ESC4)."
        ),
        technique=(
            "Modify the certificate template's Active Directory object attributes to enable "
            "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and Client Authentication EKU, converting it to ESC1 for domain takeover."
        ),
        mitre_id="T1098",
        mitre_name="Account Manipulation",
        noise_score=1.0,
    ),
    "ADCSHostRelay": EdgeExplanation(
        edge_type="ADCSHostRelay",
        description=(
            "The Active Directory Certificate Services (AD CS) Enterprise CA exposes an HTTP web enrollment "
            "endpoint (/certsrv/) without Extended Protection for Authentication (EPA) or SSL (ESC8)."
        ),
        technique=(
            "Coerce machine authentication from a high-value host (e.g. Domain Controller via MS-EFSR PetitPotam), "
            "relay the NTLM authentication to the ADCS HTTP endpoint, and obtain a domain machine certificate."
        ),
        mitre_id="T1557.001",
        mitre_name="Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
        noise_score=4.0,
    ),
}


def get_edge_explanation(edge_type: str) -> EdgeExplanation:
    """Retrieve explanation for an edge type, returning a safe default if unknown."""
    if edge_type in EDGE_EXPLANATIONS:
        return EDGE_EXPLANATIONS[edge_type]

    return EdgeExplanation(
        edge_type=edge_type,
        description=f"Relationship of type '{edge_type}' connects the source to target.",
        technique=f"Abuse relationship '{edge_type}' to gain access or privileges on target.",
        mitre_id="T1078",
        mitre_name="Valid Accounts",
        noise_score=2.0,
    )


@dataclass
class ExplainedHop:
    """Detailed narrative breakdown of an individual hop in the attack path."""

    step: int
    source_name: str
    source_type: str
    edge_type: str
    target_name: str
    target_type: str
    noise_score: float
    description: str
    technique: str
    mitre_id: str
    mitre_name: str


@dataclass
class ExplainResult:
    """Complete narrative explanation of an attack path."""

    start_name: str
    start_type: str
    target_name: str
    target_type: str
    hops_count: int
    total_noise_score: float
    chain: str
    attack_chain_summary: str
    hops: list[ExplainedHop] = field(default_factory=list)
    path_id: int | str | None = None
    llm_narrative: str | None = None

    def get_risk_assessment(self) -> str:
        """Categorize path overall detection risk based on total noise score."""
        score = self.total_noise_score
        if score <= 3.0:
            return "Low (Stealthy / Predominantly Directory ACLs & Group Membership)"
        if score <= 7.0:
            return "Moderate (Audited Replication / Kerberos Delegation Traffic)"
        if score <= 12.0:
            return "High (Remote Admin Execution / Service Logons)"
        return "Critical (Active LSASS / Interactive Session Hijacking)"

    def to_dict(self) -> dict[str, Any]:
        """Convert explanation to JSON-serializable dictionary."""
        return {
            "path_id": self.path_id,
            "start": {"name": self.start_name, "type": self.start_type},
            "target": {"name": self.target_name, "type": self.target_type},
            "hops_count": self.hops_count,
            "total_noise_score": round(self.total_noise_score, 2),
            "detection_risk": self.get_risk_assessment(),
            "chain": self.chain,
            "attack_chain_summary": self.attack_chain_summary,
            "llm_narrative": self.llm_narrative,
            "hops": [
                {
                    "step": h.step,
                    "source": {"name": h.source_name, "type": h.source_type},
                    "relationship": h.edge_type,
                    "target": {"name": h.target_name, "type": h.target_type},
                    "noise_score": round(h.noise_score, 2),
                    "mitre_id": h.mitre_id,
                    "mitre_name": h.mitre_name,
                    "description": h.description,
                    "technique": h.technique,
                }
                for h in self.hops
            ],
        }

    def to_markdown(self) -> str:
        """Format the explanation as a professional Markdown report."""
        lines: list[str] = [
            "# Active Directory Attack Path Narrative",
            "",
            f"- **Path ID**: #{self.path_id if self.path_id is not None else 'N/A'}",
            f"- **Initial Compromise (Origin)**: `{self.start_name}` ({self.start_type})",
            f"- **Target Objective**: `{self.target_name}` ({self.target_type})",
            f"- **Total Hops**: {self.hops_count}",
            f"- **Total Noise Score**: {self.total_noise_score:.1f} ({self.get_risk_assessment()})",
            f"- **Graph Traversal**: `{self.chain}`",
            "",
        ]

        if self.llm_narrative:
            lines.extend([
                "## Senior Red Team Attacker Narrative (AI Narrated)",
                f"> {self.llm_narrative}",
                "",
            ])

        lines.extend([
            "## Attack Chain Summary",
            f"**{self.attack_chain_summary}**",
            "",
            "## Step-by-Step Traversal Breakdown",
            "",
        ])

        for hop in self.hops:
            lines.extend([
                f"### Hop {hop.step}: `{hop.source_name}` ──[{hop.edge_type}]──> `{hop.target_name}`",
                "",
                f"- **Edge Relationship**: `{hop.edge_type}`",
                f"- **MITRE ATT&CK**: [{hop.mitre_id}](https://attack.mitre.org/techniques/{hop.mitre_id.replace('.', '/')}) - {hop.mitre_name}",
                f"- **Detection Noise Score**: {hop.noise_score:.1f}",
                f"- **Vulnerability / Access Meaning**:",
                f"  > {hop.description}",
                f"- **Attacker Exploitation Technique**:",
                f"  > {hop.technique}",
                "",
            ])

        lines.extend([
            "## Defensive Recommendations",
            "",
            "- Audit and remove excessive object permissions and unneeded administrative delegates.",
            "- Implement Tiered Administration (Tier 0 / Tier 1 / Tier 2 isolation) to prevent privilege escalation from workstations.",
            "- Enforce credential hygiene: rotate service account passwords and disable reversible encryption.",
            "- Monitor Event IDs 4662 (Directory Object Access), 4724 (Password Reset), and 4728/4732 (Group Membership Changes).",
            "",
        ])

        return "\n".join(lines)


def explain_path(path_data: dict[str, Any] | Any, path_id: int | str | None = None) -> ExplainResult:
    """
    Generate an attacker-reasoning narrative from a PathResult or dict representation.

    Args:
        path_data: PathResult instance or dictionary from find_path / SQLite paths table.
        path_id: Optional short path identifier.

    Returns:
        ExplainResult with detailed narrative, MITRE mappings, and attack chain summary.
    """
    # If path_data is a PathResult dataclass object, convert to dict
    if hasattr(path_data, "to_dict"):
        data = path_data.to_dict()
    elif isinstance(path_data, dict):
        data = dict(path_data)
    else:
        raise ValueError(f"Unsupported path data type: {type(path_data).__name__}")

    start = data.get("start", {})
    target = data.get("target", {})
    start_name = str(start.get("name", "Unknown Origin"))
    start_type = str(start.get("type", "Unknown"))
    target_name = str(target.get("name", "Unknown Target"))
    target_type = str(target.get("type", "Unknown"))

    chain = str(data.get("chain", ""))
    segments = data.get("segments", [])
    resolved_path_id = path_id if path_id is not None else data.get("path_id")

    hops: list[ExplainedHop] = []
    technique_summaries: list[str] = []
    total_noise: float = 0.0

    for idx, seg in enumerate(segments, 1):
        edge_type = seg.get("edge_type") or seg.get("relationship", "Unknown")
        expl = get_edge_explanation(edge_type)

        src = seg.get("source", {})
        tgt = seg.get("target", {})
        src_name = str(src.get("name", f"Node_{idx}"))
        src_type = str(src.get("type", "Unknown"))
        tgt_name = str(tgt.get("name", f"Node_{idx+1}"))
        tgt_type = str(tgt.get("type", "Unknown"))

        weight = float(seg.get("weight", expl.noise_score))
        total_noise += weight

        hop = ExplainedHop(
            step=idx,
            source_name=src_name,
            source_type=src_type,
            edge_type=edge_type,
            target_name=tgt_name,
            target_type=tgt_type,
            noise_score=weight,
            description=expl.description,
            technique=expl.technique,
            mitre_id=expl.mitre_id,
            mitre_name=expl.mitre_name,
        )
        hops.append(hop)
        technique_summaries.append(f"{expl.mitre_name} ({expl.mitre_id})")

    # If segments was empty but a chain string was provided, attempt to parse hops
    if not hops and chain:
        hops, total_noise, technique_summaries = _parse_hops_from_chain(chain)

    # Build one-line attack chain summary
    if technique_summaries:
        attack_chain_summary = " -> ".join(technique_summaries)
    else:
        attack_chain_summary = "Direct Compromise"

    hops_count = len(hops) or int(data.get("hops", 0))

    return ExplainResult(
        start_name=start_name,
        start_type=start_type,
        target_name=target_name,
        target_type=target_type,
        hops_count=hops_count,
        total_noise_score=total_noise,
        chain=chain,
        attack_chain_summary=attack_chain_summary,
        hops=hops,
        path_id=resolved_path_id,
    )


def _parse_hops_from_chain(chain: str) -> tuple[list[ExplainedHop], float, list[str]]:
    """Parse a textual chain like 'NodeA ──[Edge]──> NodeB ──[Edge2]──> NodeC'."""
    pattern = re.compile(r"──\[([^\]]+)\]──>|->")
    parts = pattern.split(chain)
    # Check if format matched
    matches = re.findall(r"──\[([^\]]+)\]──>", chain)
    node_names = [p.strip() for p in re.split(r"──\[[^\]]+\]──>", chain) if p.strip()]

    hops: list[ExplainedHop] = []
    technique_summaries: list[str] = []
    total_noise: float = 0.0

    if len(node_names) >= 2 and len(matches) == len(node_names) - 1:
        for i, edge in enumerate(matches):
            src_name = node_names[i]
            tgt_name = node_names[i + 1]
            expl = get_edge_explanation(edge)
            total_noise += expl.noise_score
            hops.append(
                ExplainedHop(
                    step=i + 1,
                    source_name=src_name,
                    source_type="Principal",
                    edge_type=edge,
                    target_name=tgt_name,
                    target_type="Principal",
                    noise_score=expl.noise_score,
                    description=expl.description,
                    technique=expl.technique,
                    mitre_id=expl.mitre_id,
                    mitre_name=expl.mitre_name,
                )
            )
            technique_summaries.append(f"{expl.mitre_name} ({expl.mitre_id})")

    return hops, total_noise, technique_summaries


def explain_path_llm(
    path_data: dict[str, Any] | Any,
    api_key: str | None = None,
    model: str = "claude-sonnet-4-6",
) -> str | None:
    """
    Generate a natural red-team narrative for an attack path using the Anthropic API.

    Calls Claude (default claude-sonnet-4-6) passing ONLY structured graph path data.
    Explicitly instructs the model not to invent nodes, edges, or facts not present,
    and flags any uncertainties.

    Returns:
        str: Natural narrative paragraph with ATT&CK IDs, or None if ANTHROPIC_API_KEY
             is not configured or if the API call fails.
    """
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not key or not key.strip():
        return None

    try:
        import anthropic
    except ImportError:
        return None

    explanation = explain_path(path_data)
    structured_context = {
        "origin": {"name": explanation.start_name, "type": explanation.start_type},
        "target": {"name": explanation.target_name, "type": explanation.target_type},
        "hops_count": explanation.hops_count,
        "total_noise_score": explanation.total_noise_score,
        "detection_risk_level": explanation.get_risk_assessment(),
        "graph_traversal": explanation.chain,
        "hops": [
            {
                "step": h.step,
                "source": {"name": h.source_name, "type": h.source_type},
                "relationship": h.edge_type,
                "target": {"name": h.target_name, "type": h.target_type},
                "mitre_id": h.mitre_id,
                "mitre_technique": h.mitre_name,
                "noise_score": h.noise_score,
                "access_meaning": h.description,
                "concrete_technique": h.technique,
            }
            for h in explanation.hops
        ],
    }

    system_prompt = (
        "You are a senior red team operator and Active Directory offensive security specialist "
        "narrating an attack path discovered during an enterprise assessment.\n\n"
        "Your task: Turn the provided structured graph traversal into a cohesive, realistic "
        "attack narrative describing how the adversary pivots from the initial compromise to the objective.\n\n"
        "CRITICAL RULES:\n"
        "1. Rely ONLY on the provided nodes, relationships, and attributes in the structured input.\n"
        "2. DO NOT invent, hallucinate, or assume any principals, hosts, edges, or credentials not in the input.\n"
        "3. Explicitly cite the provided MITRE ATT&CK technique IDs (e.g. T1098, T1003.001, T1649) as each step is narrated.\n"
        "4. If there is any ambiguity or uncertainty regarding a step, explicitly flag it.\n"
        "5. Conclude with a one-sentence summary of the attack chain."
    )

    try:
        client = anthropic.Anthropic(api_key=key)
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Here is the structured attack path data:\n\n"
                        f"{json.dumps(structured_context, indent=2)}\n\n"
                        f"Please provide your senior red team narrative:"
                    ),
                }
            ],
        )
        if response.content and len(response.content) > 0:
            block = response.content[0]
            if hasattr(block, "text"):
                return block.text.strip()
    except Exception:
        return None

    return None


