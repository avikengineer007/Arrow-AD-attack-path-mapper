# Active Directory Certificate Services (AD CS) Attack Paths & Detection Guide

This document details the detection methodology, graph modeling, and false-positive analysis for **Active Directory Certificate Services (AD CS)** vulnerabilities in **Arrow**: **ESC1**, **ESC4**, and **ESC8**.

---

## 1. Overview of AD CS Attack Graphs

Active Directory Certificate Services (AD CS) is Microsoft's Public Key Infrastructure (PKI) implementation for enterprise identity, encryption, and authentication. PKI configurations in Active Directory are published directly in the **Configuration Naming Context**:
```text
CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>
├── CN=Certificate Templates
├── CN=Enrollment Services (Enterprise CAs)
├── CN=Certification Authorities
└── CN=AIA
```

When misconfigured, AD CS templates and enrollment endpoints permit low-privilege principals to obtain valid X.509 certificates impersonating arbitrary high-privilege domain accounts (e.g. Domain Administrators or Domain Controllers), leading to instantaneous domain takeover.

---

## 2. ESC1: Enrollee Supplies Subject Alternative Name (SAN) + Client Authentication

### Vulnerability Mechanics & Impact
ESC1 occurs when an Active Directory certificate template is published on an active Enterprise CA with settings that allow the certificate requester to specify an arbitrary Subject Alternative Name (SAN) alongside an Extended Key Usage (EKU) permitting Kerberos/Schannel client authentication.

An attacker with enrollment rights requests a certificate for themselves, but injects the User Principal Name (UPN) or DNS name of `Administrator` into the SAN. Once the CA issues the certificate, the attacker performs Kerberos PKINIT authentication (e.g. via Rubeus or Certipy) to receive a high-privilege Kerberos Ticket Granting Ticket (TGT).

### Detection Logic & LDAP Attributes

Arrow inspects `pKICertificateTemplate` objects under `CN=Certificate Templates,CN=Public Key Services,...` against four prerequisite conditions:

| Parameter | LDAP Attribute | Vulnerable Condition |
| :--- | :--- | :--- |
| **Enrollee Supplies SAN** | `msPKI-Certificate-Name-Flag` | `(msPKI-Certificate-Name-Flag & 0x00000001) != 0`<br/>(`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) |
| **Client Authentication EKU** | `pKIExtendedKeyUsage` | Contains `1.3.6.1.5.5.7.3.2` (Client Auth), `1.3.6.1.4.1.311.20.2.2` (Smart Card Logon), `1.3.6.1.5.2.3.4` (PKINIT), `2.5.29.37.0` (Any Purpose), or empty EKU |
| **Manager Approval** | `msPKI-Enrollment-Flag` | `(msPKI-Enrollment-Flag & 0x00000002) == 0`<br/>(CA manager approval is **NOT** required) |
| **Authorized Signatures** | `msPKI-RA-Signature` | `msPKI-RA-Signature <= 0`<br/>(Zero authorized signatures required) |
| **Enrollment Permissions** | `nTSecurityDescriptor` | Non-admin group (e.g. `Domain Users`, `Authenticated Users`) possesses `Enroll` or `GenericAll` in the DACL |

### False-Positive Caveats & Validation Edge Cases
1. **CA Manager Approval Enabled (`CT_FLAG_PEND_ALL_REQUESTS`)**:
   - If `msPKI-Enrollment-Flag` has bit `0x00000002` set, certificate requests enter a "Pending" queue requiring a CA Officer to manually approve issuance. The attack cannot proceed automatically without out-of-band social engineering or compromised CA operator credentials.
2. **Template Not Published on Active CA**:
   - A certificate template may exist in the `CN=Certificate Templates` container with vulnerable settings, but unless it is published in the `certificateTemplates` multi-valued attribute of at least one active Enterprise CA (`pKIEnrollmentService`), it cannot be enrolled. Arrow cross-references published CA lists to eliminate dormant templates.
3. **Restricted Enrollee Groups**:
   - If enrollment rights are restricted exclusively to Tier-0 administrative groups (e.g. Domain Admins), this does not constitute a privilege escalation path. Arrow flags ESC1 only when low-privilege principals or broad groups (`Domain Users`, `Domain Computers`, `Authenticated Users`) have enrollment access.
4. **Issuance Policies & Application Policies**:
   - Templates requiring specific object identifier (OID) issuance requirements or Enrollment Agent signatures (`1.3.6.1.4.1.311.20.2.1`) cannot be directly enrolled by standard users.

---

## 3. ESC4: Misconfigured Certificate Template DACL (Template Overwrite)

### Vulnerability Mechanics & Impact
ESC4 arises when an Active Directory certificate template has a weak Access Control List (DACL) that grants non-administrative principals write permissions (`GenericAll`, `GenericWrite`, `WriteDacl`, or `WriteOwner`) over the template object.

An attacker who possesses write access over a certificate template does not need the template to be currently vulnerable. Instead, the attacker edits the template's LDAP attributes in Active Directory to enable `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, adds the Client Authentication EKU, sets manager approval to False, and grants themselves enrollment rights—effectively converting the template into **ESC1**. After enrolling and impersonating Domain Admins, the attacker restores the original template parameters to cover their tracks.

### Detection Logic & LDAP Attributes

Arrow checks each `pKICertificateTemplate` object's binary `nTSecurityDescriptor` Discretionary Access Control List (DACL):

```python
# ACE rights checked on target_node_type="CertTemplate":
if edge_type in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner"):
    if not is_default_admin(trustee_sid):
        # Flagged as ESC4
```

### False-Positive Caveats
1. **Default Administrative Trustees**:
   - In standard Active Directory installations, `Domain Admins`, `Enterprise Admins`, and `SYSTEM` hold `GenericAll` over all certificate templates by default. Arrow filters out default administrative trustees to avoid false positives and highlight only actionable privilege escalation exposures.
2. **Inherited vs. Explicit Deny ACEs**:
   - An explicit `Deny` Access Control Entry on the template takes precedence over inherited `Allow` entries in Windows security descriptors. Arrow evaluates DACL ordering to ensure permissions are effective.

---

## 4. ESC8: NTLM Relay to HTTP Web Enrollment Endpoint (`/certsrv/`)

### Vulnerability Mechanics & Impact
ESC8 targets Microsoft AD CS Web Enrollment (typically exposed under `http://<caserver>/certsrv/`). By default, the Internet Information Services (IIS) virtual directory for AD CS Web Enrollment supports NTLM authentication without enforcing **Extended Protection for Authentication (EPA)** or SSL/TLS channel binding.

An attacker leverages a machine authentication coercion primitive (such as **PetitPotam** / `MS-EFSR`, **PrinterBug** / `MS-RPRN`, or WebDAV) to force a Domain Controller (or high-privilege computer) to authenticate to an attacker-controlled listener over SMB. The attacker relays the Domain Controller's NTLM authentication to the AD CS Web Enrollment HTTP endpoint (`/certsrv/certfnsh.asp`), enrolls a computer certificate on behalf of the Domain Controller, and authenticates as the DC via PKINIT to extract KRBTGT password hashes.

### Detection Logic & Network Indicators

Arrow inspects `pKIEnrollmentService` objects and CA host attributes:

| Component | Property | Condition |
| :--- | :--- | :--- |
| **Enterprise CA** | `dNSHostName` | Computer hosting the CA |
| **Web Enrollment Endpoint** | HTTP URL | `http://<caserver>/certsrv/` |
| **EPA Enforcement** | `epa_enabled` | `False` (EPA not enforced) |
| **Transport Encryption** | `ssl_required` | `False` (Cleartext HTTP allowed) |

In Arrow's graph, each non-admin computer account is connected to the Enterprise CA via the **`ADCSHostRelay`** edge.

### False-Positive Caveats
1. **EPA Enabled in IIS**:
   - If Extended Protection for Authentication is configured (`extendedProtection = "Required"` or `"Allowed"` with Channel Binding Tokens in `applicationHost.config`), NTLM authentication relayed across protocols (SMB -> HTTP) will be rejected by IIS.
2. **HTTP Disabled / HTTPS Enforced**:
   - If port 80 (HTTP) is disabled and `/certsrv/` strictly requires HTTPS with EPA, relaying without TLS termination/MITM fails.
3. **Web Enrollment Role Not Installed**:
   - An Enterprise CA can exist in the domain without the optional `Certification Authority Web Enrollment` role installed. Arrow notes endpoint status during live collection.

---

## 5. Arrow CLI AD CS Commands

Inspect and query AD CS misconfigurations directly from Arrow:

```bash
# Query all certificate templates vulnerable to ESC1:
arrow query esc1

# Query certificate templates with weak DACLs (ESC4):
arrow query esc4

# Query Enterprise CAs with vulnerable HTTP web enrollment (ESC8):
arrow query esc8

# Comprehensive aggregated AD CS audit:
arrow query adcs

# Find attack paths involving AD CS enrollment:
arrow path "victim_bob" --to "Domain Admins" --stealth
```

---

## 6. Hardening & Remediation Checklist

1. **Remediate ESC1**:
   - For all certificate templates permitting client authentication, uncheck **"Supply in the request"** under the **Subject Name** tab in `certtmpl.msc`; set to **"Build from this Active Directory information"**.
   - If custom SANs are genuinely required, enforce **CA Certificate Manager Approval** (`CT_FLAG_PEND_ALL_REQUESTS`).
2. **Remediate ESC4**:
   - Audit template DACLs using `certtmpl.msc` or Arrow. Revoke all non-administrative write permissions (`GenericAll`, `WriteDacl`, `WriteOwner`, `GenericWrite`). Ensure only `Domain Admins` and `Enterprise Admins` manage templates.
3. **Remediate ESC8**:
   - If AD CS Web Enrollment (`/certsrv/`) is not required, uninstall the role service:
     ```powershell
     Uninstall-WindowsFeature ADCS-Web-Enrollment
     ```
   - If Web Enrollment is required:
     1. Enforce HTTPS only (remove port 80 bindings).
     2. Enable Extended Protection for Authentication (EPA) in IIS under `/certsrv/`:
        ```powershell
        Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/windowsAuthentication/extendedProtection" -Name "tokenChecking" -Value "Require"
        ```
     3. Disable NTLM authentication and enforce Negotiate (Kerberos only).

