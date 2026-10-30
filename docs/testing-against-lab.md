# 🧪 Arrow Lab Integration Testing Guide

This guide details how to stand up a dedicated Active Directory test lab and plant deliberate misconfigurations to validate **Arrow's** live LDAP ingestion, ACL parsing, and attack-path analysis against known-answer scenarios.

---

## 1. Lab Setup Options

### Option A: Game of Active Directory (GOAD) (Recommended)
GOAD by Orange-Cyberdefense is a pre-configured multi-host vulnerable Active Directory lab:
- **Repository**: [https://github.com/Orange-Cyberdefense/GOAD](https://github.com/Orange-Cyberdefense/GOAD)
- **Flavor**: `GOAD-Light` (1 DC `sevenkingdoms.local` + 2 servers) or full `GOAD` (multi-forest).
- **Deployment**: Automated via Vagrant + VirtualBox or Proxmox:
  ```bash
  git clone https://github.com/Orange-Cyberdefense/GOAD
  cd GOAD
  ./goad.sh -t check -p virtualbox -m goad-light
  ./goad.sh -t install -p virtualbox -m goad-light
  ```

---

### Option B: Manual Minimal Lab (1 DC + 2 Member Workstations)
If building manually using Hyper-V, VirtualBox, or VMware:
1. **Domain Controller**: Windows Server 2022 (Hostname: `DC01`, IP: `192.168.56.10`, Domain: `lab.local`).
2. **Workstations**:
   - `WS01`: Windows 11 Enterprise (`192.168.56.20`)
   - `WS02`: Windows 11 Enterprise (`192.168.56.21`)

#### Quick AD Forest Setup (PowerShell on DC01):
```powershell
# Install Active Directory Domain Services
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest `
    -DomainName "lab.local" `
    -DomainNetbiosName "LAB" `
    -DomainMode "WinThreshold" `
    -ForestMode "WinThreshold" `
    -InstallDns $true `
    -Force $true
```

---

## 2. Planting Known-Answer Misconfigurations

Execute the following PowerShell commands on `DC01` to plant verifiable attack paths.

### 🎯 Misconfiguration 1: Nested Group Path to Domain Admins
Create a tiered delegation chain leading to `Domain Admins`:
$$\text{contractor\_bob} \xrightarrow{\text{MemberOf}} \text{Tier2 Support} \xrightarrow{\text{MemberOf}} \text{IT Operations} \xrightarrow{\text{MemberOf}} \text{Domain Admins}$$

```powershell
# Create user
New-ADUser -Name "contractor_bob" -SamAccountName "contractor_bob" -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true

# Create groups
New-ADGroup -Name "Tier2 Support" -GroupScope Global
New-ADGroup -Name "IT Operations" -GroupScope Global

# Nest memberships
Add-ADGroupMember -Identity "Tier2 Support" -Members "contractor_bob"
Add-ADGroupMember -Identity "IT Operations" -Members "Tier2 Support"
Add-ADGroupMember -Identity "Domain Admins" -Members "IT Operations"
```

#### Validation with Arrow:
```bash
arrow ingest --dc 192.168.56.10 -d lab.local -u contractor_bob -p 'Password123!'
arrow path contractor_bob --to "Domain Admins"
```
**Expected Path**:
`contractor_bob ──[MemberOf]──> Tier2 Support ──[MemberOf]──> IT Operations ──[MemberOf]──> Domain Admins`

---

### 🎯 Misconfiguration 2: GenericAll on a Kerberoastable Service Account
Grant a low-privilege user full control (`GenericAll`) over an account with a Service Principal Name (SPN).

```powershell
# Create service account with SPN
New-ADUser -Name "svc_mssql" -SamAccountName "svc_mssql" -AccountPassword (ConvertTo-SecureString "ServicePass123!" -AsPlainText -Force) -Enabled $true
Set-ADUser -Identity "svc_mssql" -ServicePrincipalNames @{Add='MSSQLSvc/SQL01.lab.local:1433'}

# Grant contractor_bob GenericAll over svc_mssql
$TargetUser = Get-ADUser -Identity "svc_mssql"
$TargetDN = $TargetUser.DistinguishedName
$Trustee = Get-ADUser -Identity "contractor_bob"
$TrusteeSID = [System.Security.Principal.SecurityIdentifier]$Trustee.SID

$Acl = Get-Acl -Path "AD:$TargetDN"
$Ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $TrusteeSID,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$Acl.AddAccessRule($Ace)
Set-Acl -Path "AD:$TargetDN" -AclObject $Acl
```

#### Validation with Arrow:
```bash
# 1. Audit Kerberoastable Accounts:
arrow query kerberoastable

# 2. Query Direct Attack Path:
arrow path contractor_bob --to svc_mssql
```
**Expected Path**:
`contractor_bob ──[GenericAll]──> svc_mssql`

---

### 🎯 Misconfiguration 3: Unconstrained Delegation on a Member Server
Configure a member server for unconstrained Kerberos delegation (`TRUSTED_FOR_DELEGATION` = 0x80000):

```powershell
# Create computer object
New-ADComputer -Name "SRV-WEB01" -SamAccountName "SRV-WEB01$"

# Enable Unconstrained Delegation
Set-ADAccountControl -Identity "SRV-WEB01$" -TrustedForDelegation $true
```

#### Validation with Arrow:
```bash
arrow query unconstrained
```
**Expected Output**:
Table lists `SRV-WEB01.LAB.LOCAL` with `unconstraineddelegation = True`.

---

### 🎯 Misconfiguration 4: AS-REP Roastable Account (`DONT_REQ_PREAUTH`)
Configure an account without Kerberos pre-authentication required:

```powershell
New-ADUser -Name "legacy_app" -SamAccountName "legacy_app" -AccountPassword (ConvertTo-SecureString "LegacyPass123!" -AsPlainText -Force) -Enabled $true
Set-ADAccountControl -Identity "legacy_app" -DoesNotRequirePreAuth $true
```

#### Validation with Arrow:
```bash
arrow query asrep
```
**Expected Output**:
Table lists `legacy_app@LAB.LOCAL` with `PreAuth Required = FALSE (Vulnerable)`.

---

## 3. Arrow Live Collection Commands Reference

### Standard Ingestion (Standard Domain User)
A standard domain user has permission to query all LDAP objects and read security descriptors by default in Active Directory:
```bash
arrow ingest --dc 192.168.56.10 -d lab.local -u contractor_bob -p 'Password123!'
```

### Anonymous Bind Testing
Test if the domain controller allows unauthenticated directory queries:
```bash
arrow ingest --dc 192.168.56.10 -d lab.local --anonymous
```

### Secure LDAPS Collection
```bash
arrow ingest --dc 192.168.56.10 -d lab.local -u contractor_bob -p 'Password123!' --ldaps
```

### Host Local Admin & Active Session Collection (`--local-admin`)
> [!NOTE]
> Queries host SMB endpoints (TCP 445) via SAMR and NetSessionEnum. This requires local administrator credentials on remote workstations:
```bash
arrow ingest --dc 192.168.56.10 -d lab.local -u domain_admin -p 'AdminPass123!' --local-admin
```

---

## 4. Post-Ingest Validation Checklist

After running `arrow ingest`:

- [ ] Run `arrow graph info`: Verify expected node counts (Domain, Users, Groups, Computers).
- [ ] Run `arrow query kerberoastable`: Verify `svc_mssql` is discovered.
- [ ] Run `arrow query asrep`: Verify `legacy_app` is discovered.
- [ ] Run `arrow query unconstrained`: Verify `SRV-WEB01` is discovered.
- [ ] Run `arrow path contractor_bob --to "Domain Admins"`: Verify 3-hop nested group path.
- [ ] Run `arrow blast contractor_bob --to-da`: Verify blast radius confirms `Domain Admins` is reachable.

