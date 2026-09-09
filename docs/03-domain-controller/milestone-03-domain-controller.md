# Milestone 3 — Windows Server 2025 Install & AD DS Promotion (Domain Controller)

**Phase:** 1 — Lab foundations
**Status:** Complete
**Score:** 93/100
**Host:** `DC01.lab.local` — `10.10.10.10/24` on VMnet2
**Date completed:** 8 September 2026

---

## 1. Objective

Build the identity backbone of the lab: install Windows Server 2025, configure it as a
statically addressed host on the isolated `10.10.10.0/24` network, and promote it to be the
first domain controller of a new Active Directory forest, `lab.local`.

On completion the lab has a working Kerberos KDC, an authoritative DNS server, a global
catalog, and the SYSVOL/NETLOGON shares that Group Policy depends on. Every subsequent
milestone builds on this: the OU and GPO structure in Milestone 4, the domain join in
Milestone 5, and — from Milestone 7 onward — the Windows Security event log that Wazuh
correlates against.

---

## 2. Why this matters to an employer

Active Directory is the identity layer of the overwhelming majority of UK enterprises, and
it is the primary target in most real intrusions. A SOC analyst who cannot read AD
telemetry cannot investigate lateral movement, credential theft, privilege escalation, or
persistence — which is most of what lands in the queue above tier 1.

Building a domain controller by hand rather than importing a prebuilt appliance means the
log sources in later phases are understood rather than inherited. When a Wazuh alert fires
on Event ID 4768 in Phase 3, the Kerberos ticket request it represents traces back to the
KDC stood up here.

Specific hiring-relevant competencies demonstrated:

- AD DS forest deployment and the FSMO role model
- The dependency between AD and DNS, and why it is not optional
- Pre-promotion sequencing and the cost of getting it wrong
- Reading and classifying prerequisite failures rather than clicking through them
- Verifying claimed state from the command line instead of trusting a wizard's summary

---

## 3. Concepts involved

**Forest, domain, tree.** The forest is the outermost security boundary in AD. A domain is
an administrative and replication partition within it. `lab.local` is a single-domain forest
— the simplest topology, and the correct one for a lab of this size.

**FSMO roles.** Five single-instance roles that cannot be held concurrently by multiple DCs:

| Role | Scope | Function |
|---|---|---|
| Schema Master | Forest | Owns the only writeable copy of the AD schema |
| Domain Naming Master | Forest | Authorises addition and removal of domains |
| PDC Emulator | Domain | Authoritative time source; handles legacy replication, password change urgency, lockout processing |
| RID Master | Domain | Issues blocks of relative identifiers for SID generation |
| Infrastructure Master | Domain | Maintains cross-domain object references |

The first DC in a new forest holds all five by definition.

**AD and DNS.** AD DS does not merely prefer DNS — it is unusable without it. Clients locate
domain controllers by querying SRV records under `_msdcs.<domain>`; Kerberos authentication
requires resolving the KDC by name. A DC must therefore resolve against a DNS server holding
its own service records, which in a single-DC forest means itself. Pointing a DC at an
external resolver is a classic misconfiguration that produces failures which look unrelated
to DNS.

**DC Locator.** The mechanism by which an unconfigured client finds a domain. Records follow
the pattern `_service._protocol[.role]._msdcs.domain`, where `role` distinguishes any DC
(`dc`), the PDC Emulator (`pdc`), and a global catalog (`gc`).

**DSRM.** Directory Services Restore Mode — a boot mode that starts the server with the AD
database offline for repair or authoritative restore. Its password is set at promotion time
and is distinct from any domain credential. It is needed precisely when normal domain
authentication is unavailable, which is why it must be recorded outside the domain.

**Functional levels.** Set the floor for available AD features by constraining the minimum
supported DC OS version. `Windows2025` is correct here as there are no legacy DCs to
interoperate with. Raising a functional level is straightforward; lowering it is not.

---

## 4. Design decisions

### 4.1 `.local` as the forest root suffix

`.local` is reserved by RFC 6762 for multicast DNS, and Microsoft has advised against it for
AD domains for years. Current guidance is a delegated subdomain of an owned public domain
(`ad.example.com`) or the `.internal` special-use TLD.

**Decision: retained `lab.local`.** In a fully isolated network with no mDNS responders and
no external DNS integration, the conflict cannot manifest. The name was already fixed in the
Milestone 1–2 documentation and architecture diagram.

**In production this would be wrong**, and the reason is worth stating plainly: an mDNS
resolver on a client may intercept `.local` queries before they reach the AD DNS server,
producing intermittent, host-specific authentication failures that are difficult to diagnose.
Renaming a forest post-promotion is a high-risk operation, so the choice is effectively
permanent.

### 4.2 Pre-promotion sequencing

Executed in this order: **rename → static IP → snapshot → promote.**

Renaming a member server is a single cmdlet and a reboot. Renaming a domain controller
requires `netdom computername`, SPN updates, and DNS record churn, with a window in which
clients cannot locate the DC. Addressing was fixed before promotion because the DC registers
its A and SRV records against whatever address it holds at promotion time.

### 4.3 No default gateway

Deliberately omitted. There is no route out of `10.10.10.0/24` by design (Milestone 2), so a
gateway address would point at nothing. This is the isolation design expressed in host
configuration rather than only in the hypervisor.

### 4.4 Database, log and SYSVOL paths

Defaults accepted (`C:\Windows\NTDS`, `C:\Windows\SYSVOL`). Production practice separates the
NTDS database and its transaction logs onto distinct volumes for write-throughput and
recovery-isolation reasons. Accepted knowingly here: single virtual disk, no I/O contention
at lab scale.

### 4.5 Time authority — **OUTSTANDING**

Two competing clock authorities exist on a virtualised DC: VMware Tools host-guest
synchronisation, and `w32time` with the PDC Emulator acting as authoritative source for the
domain. `dcdiag` confirms DC01 as Preferred Time Server for `lab.local`.

This decision is **not yet made or documented** and is the outstanding item against this
milestone. It must be resolved before Milestone 9 (log ingestion validation), because
timestamp disagreement across DC, client and Wazuh manager breaks event correlation —
sequencing an attack chain requires trustworthy ordering across log sources.

---

## 5. Implementation

### 5.1 Install

Windows Server 2025 **Standard (Desktop Experience)**. GUI retained deliberately: screenshot
evidence for portfolio documentation, and the graphical AD administration tools needed in
Milestone 4. Server Core would be the defensible production choice for a DC.

VM configuration: UEFI firmware, network adapter attached to **VMnet2** (host-only, DHCP
disabled).

### 5.2 Rename

```powershell
Rename-Computer -NewName "DC01" -Restart
```

`DC01` is within the 15-character NetBIOS limit and contains no reserved characters.

### 5.3 Static addressing

```powershell
Get-NetAdapter
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 10.10.10.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 10.10.10.10
```

No `-DefaultGateway` parameter — see §4.3.

### 5.4 Snapshot

VMware snapshot taken as `M3-pre-promotion` before invoking the promotion. Promotion is not
cleanly reversible.

### 5.5 Prerequisite failure — blank local Administrator password

The prerequisites check returned a **hard failure**:

> Administrator account becomes the domain Administrator account when you create a new
> domain. The new domain cannot be created because the local Administrator account password
> does not meet requirements.

**Cause.** Promotion converts the existing local Administrator into the first Domain Admin of
the forest, inheriting its password. That account was left with a blank password after
installation.

**Why AD blocks rather than warns.** Domain Admin is the highest-privilege principal in the
forest. A Domain Admin with no password is equivalent to total domain compromise from any
host that can reach the DC, so the condition is refused at creation time rather than reported
as a warning.

**Fix, executed inside the guest:**

```powershell
net user Administrator *
```

Prerequisites check rerun → passed.

**Carried forward:** monitoring changes to Domain Admins group membership is an early
detection candidate for Phase 3.

### 5.6 Promotion

Configured through the AD DS Configuration Wizard, with the equivalent PowerShell exported
via **Review Options → View script** and retained as
[`scripts/install-addsforest.ps1`](../scripts/install-addsforest.ps1):

```powershell
Import-Module ADDSDeployment
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\WINDOWS\NTDS" `
-DomainMode "Win2025" `
-DomainName "lab.local" `
-DomainNetbiosName "LAB" `
-ForestMode "Win2025" `
-InstallDns:$true `
-LogPath "C:\WINDOWS\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\WINDOWS\SYSVOL" `
-Force:$true
```

Capabilities: DNS server and Global Catalog enabled. RODC unavailable — the first DC in a
forest must hold a writeable copy.

---

## 6. Warnings classified

Distinguishing expected warnings from genuine faults is the substantive analytical work in
this milestone.

| Warning | Classification | Reasoning |
|---|---|---|
| DNS delegation for `lab.local` cannot be created; authoritative parent zone not found | **Expected** | No parent zone exists for `.local` and there is no external DNS infrastructure to delegate from. The wizard itself states no action is required. |
| Server reboots automatically at end of promotion | **Informational** | Expected behaviour; `-NoRebootOnCompletion:$false`. |
| Blank local Administrator password | **Genuine failure — fixed** | See §5.5. |

---

## 7. Post-promotion validation

Login prompt presented `LAB\Administrator` rather than `DC01\Administrator` — first
confirmation the machine is no longer standalone.

### 7.1 Domain and forest identity

```powershell
Get-ADDomain | Select-Object DNSRoot,NetBIOSName,DomainMode,DistinguishedName
```

| Property | Value |
|---|---|
| DNSRoot | `lab.local` |
| NetBIOSName | `LAB` |
| DomainMode | `Windows2025Domain` |
| DistinguishedName | `DC=lab,DC=local` |

### 7.2 FSMO roles

```powershell
netdom query fsmo
```

All five roles held by `DC01.lab.local` — Schema Master, Domain Naming Master, PDC, RID Pool
Manager, Infrastructure Master. Correct for a single-DC forest.

### 7.3 Services

```powershell
Get-Service ADWS,DNS,KDC,Netlogon,NTDS
```

All five running: Active Directory Web Services, DNS Server, Kerberos Key Distribution
Center, Netlogon, Active Directory Domain Services.

### 7.4 Group Policy prerequisites

```powershell
Get-SmbShare | Where-Object Name -in 'SYSVOL','NETLOGON'
```

Both shares present. `SYSVOL` → `C:\WINDOWS\SYSVOL\sysvol`;
`NETLOGON` → `C:\WINDOWS\SYSVOL\sysvol\lab.local\SCRIPTS`. These are the replicated
filesystem paths from which clients retrieve Group Policy — verified now because their
absence would surface as an unexplained GPO failure in Milestone 4.

### 7.5 DC Locator SRV records

```powershell
Resolve-DnsName -Name _ldap._tcp.dc._msdcs.lab.local  -Type SRV
Resolve-DnsName -Name _kerberos._tcp.lab.local        -Type SRV
Resolve-DnsName -Name _ldap._tcp.pdc._msdcs.lab.local -Type SRV
Resolve-DnsName -Name _ldap._tcp.gc._msdcs.lab.local  -Type SRV
```

All four resolve to `dc01.lab.local` with an additional A record at `10.10.10.10`. This is
the complete discovery path a client needs: locate a DC, locate a KDC to authenticate
against, locate the PDC Emulator, locate a global catalog. Verified here because the
Milestone 5 domain join depends on it entirely.

**Analyst note.** An initial lookup of `_ldap._msdcs.lab.local` returned `DNS name does not
exist`. The query was malformed — the record is `_ldap._tcp.dc._msdcs.lab.local`, and the
`_tcp.dc.` segment had been omitted. The DNS server answered correctly for a name that does
not exist. Recorded because misreading a correct negative answer as a fault is a realistic
triage error, and the corrected lookup confirmed registration was never in question.

### 7.6 Directory health

```powershell
dcdiag /v
dcdiag /test:DNS /v
```

`LocatorCheck` passed, reporting GC, PDC, KDC and Time Server as `\\DC01.lab.local`.
`Intersite` passed. `Default-First-Site-Name` created by default — appropriate for a
single-subnet topology.

DNS test summary for `DC01`: **Auth PASS, Basc PASS, Forw PASS, Del PASS, Dyn PASS,
RReg PASS, Ext n/a**. Delegation for `_msdcs.lab.local` reported operational on
`10.10.10.10`.

**Discrepancy investigated.** The DNS test reported all thirteen internet root servers
passing, which is inconsistent with an air-gapped network. Verified directly rather than
assumed:

```powershell
Resolve-DnsName google.com                 # → RCODE_SERVER_FAILURE
Test-NetConnection 8.8.8.8 -Port 53        # → PingSucceeded: False, TcpTestSucceeded: False
Get-NetRoute -DestinationPrefix 0.0.0.0/0  # → no matching route
```

External resolution fails, `8.8.8.8` is unreachable, and no default route exists.
`Ext: n/a` in the summary confirms external resolution was not exercised — `dcdiag` was
validating root hints *configuration*, not reachability. **Isolation confirmed.** This
matters beyond tidiness: by Phase 4 this network hosts Atomic Red Team execution against a
live domain, and an unintended egress path would change the risk profile of that work
entirely.

### 7.7 Addressing

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress,PrefixLength
```

`Ethernet0` → `10.10.10.10/24`. Matches the Milestone 2 addressing plan.

### 7.8 DNS client setting altered by promotion

```powershell
Get-DnsClientServerAddress -AddressFamily IPv4
```

Returned `{127.0.0.1}` — **not** the `10.10.10.10` set in §5.3.

The promotion rewrote the resolver to loopback when it installed the DNS role, as flagged on
the wizard's Review Options page ("This computer will be configured to use this DNS server as
its preferred DNS server"). Functionally equivalent here: both addresses reach the same DNS
service, as §7.5 demonstrates.

Reset for consistency with the documented addressing plan, and because Microsoft's guidance
for multi-DC environments is that a DC should reference a partner DC first and itself second
— loopback is not equivalent to an interface address in all replication scenarios:

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 10.10.10.10
```

Recorded because a configuration value set deliberately was silently changed by a later
operation. Verifying declared state after any privileged change is the transferable habit.

### 7.9 Final snapshot

`M3-post-promotion-validated` — the baseline Milestone 4 builds on.

---

## 8. Evidence

| # | File | Shows |
|---|---|---|
| 3.1 | `01-server-manager-roles-0.png` | Fresh install, Desktop Experience, no roles installed |
| 3.2 | `02-deployment-configuration.png` | "Add a new forest", root domain `lab.local` |
| 3.3 | `03-domain-controller-options.png` | Win2025 functional levels, DNS + GC, RODC greyed out |
| 3.4 | `04-dns-options-delegation-warning.png` | Expected delegation warning |
| 3.5 | `05-additional-options-netbios.png` | NetBIOS name `LAB` |
| 3.6 | `06-paths.png` | NTDS / SYSVOL paths |
| 3.7 | `07-review-options.png` | Summary incl. local-to-domain Administrator note |
| 3.8 | `08-view-script-export.png` | Exported `Install-ADDSForest` command |
| 3.9 | `09-prereq-check-FAILED.png` | Blank Administrator password hard failure |
| 3.10 | `10-prereq-check-PASSED.png` | Clean rerun after fix |
| 3.11 | `11-login-lab-administrator.png` | `LAB\Administrator` at login |
| 3.12 | `12-netdom-query-fsmo.png` | Five FSMO roles on DC01 |
| 3.13 | `13-dcdiag-locatorcheck.png` | GC / PDC / KDC / Time Server discovery |
| 3.14 | `14-dcdiag-dns-summary.png` | Auth/Basc/Forw/Del/Dyn/RReg all PASS |
| 3.15 | `15-srv-records.png` | Four DC Locator SRV lookups |
| 3.16 | `16-isolation-verified.png` | External DNS and 8.8.8.8 both unreachable |
| 3.17 | `17-addressing-and-dns-client.png` | `10.10.10.10/24`, no default route, resolver `127.0.0.1` |
| 3.18 | `18-dns-client-corrected.png` | Resolver reset to `10.10.10.10` |

---

## 9. Score — 93/100

| Criterion | Weight | Score | Notes |
|---|---|---|---|
| Objective met | 20 | 20 | Forest created, DC operational, all roles held |
| Correct sequencing | 10 | 10 | Rename → IP → snapshot → promote |
| Design decisions justified | 15 | 12 | `.local`, gateway, paths all reasoned. **Time authority undecided — see §4.5** |
| Reproducibility | 10 | 10 | PowerShell throughout; `Install-ADDSForest` exported and retained |
| Validation depth | 20 | 20 | FSMO, services, shares, SRV, `dcdiag`, addressing, isolation all verified from CLI |
| Fault diagnosis | 10 | 10 | Prerequisite failure and dcdiag root-hints discrepancy both investigated to root cause |
| Evidence quality | 10 | 8 | Full screenshot set; failure-and-fix pair captured. Deduct for filenames not yet normalised |
| Rollback discipline | 5 | 3 | Both snapshots taken. Deduct: pre-promotion snapshot taken at wizard stage rather than immediately post-addressing |

**Deductions to carry forward**

1. **Time authority decision outstanding.** Must be resolved and documented before Milestone 9.
2. Normalise screenshot filenames to the `NN-description.png` scheme above.
3. Snapshot immediately after each configuration change, not at the next natural pause.

---

## 10. Interview questions this milestone answers

- *Why does a domain controller point DNS at itself?*
- *What are the five FSMO roles and what breaks if the PDC Emulator is unavailable?*
- *Why is `.local` discouraged for AD domains?*
- *Why must a machine be renamed before promotion rather than after?*
- *A prerequisites check fails on the Administrator password — what is the underlying reason?*
- *`dcdiag` reports root hints passing on an air-gapped network. Is that a fault?*
- *How does a workstation with no configuration find a domain to join?*

---

## 11. Next — Milestone 4

AD structure: organisational units, user and group objects, and a baseline Group Policy
Object. Built on the `M3-post-promotion-validated` snapshot, and the first milestone to
exercise the SYSVOL and NETLOGON shares verified in §7.4.

Time authority decision (§4.5) to be resolved as part of Milestone 4 documentation.
