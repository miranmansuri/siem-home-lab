# Milestone 4: AD Structure, Accounts, Groups and Baseline GPO

**Phase:** 1, Lab foundations
**Status:** Complete
**Score:** 95/100
**Host:** `DC01.lab.local` at `10.10.10.10/24` on VMnet2
**Date completed:** 26 September 2026

---

## 1. Objective

Build the organisational structure of the domain, create the accounts and groups the rest of
the project needs, and configure the audit policy that decides what telemetry exists from
here on.

The third part is the one that carries weight. A default Windows install does not log process
creation, does not log PowerShell script content, and logs very little Kerberos activity.
That is not an oversight on Microsoft's part. Those events are high volume, and a default
install has nowhere to send them. This lab does have somewhere to send them, which changes
the calculation.

---

## 2. Why this matters to an employer

The chain runs forward from here. Audit policy set in this milestone produces events on the
client in Milestone 5. Sysmon adds process and network detail in Milestone 6. Wazuh ingests
it from Milestone 8, Milestone 9 confirms it arrives, and Phase 3 writes detection rules
against whatever is in the pipeline.

Get the audit policy wrong here and Milestone 9 still looks healthy. Logs flow, agents report
in, dashboards populate. The gap surfaces in Phase 3, when a rule needs Event 4688 and there
are no 4688 events to match on. The failure appears six milestones downstream of its cause,
which is the kind of problem that is expensive to find and cheap to prevent.

Competencies this milestone demonstrates:

- Designing an OU structure around security boundaries rather than object categories
- Knowing why containers cannot receive Group Policy and what to do about it
- Configuring Advanced Audit Policy including the override that makes it work at all
- Weighing log volume against detection value instead of enabling everything
- Investigating an unexplained privileged account and remediating it in the right order
- Telling the difference between "these events exist" and "my configuration produced them"

---

## 3. Concepts involved

**Containers and organisational units are not the same thing.** `CN=Users` and `CN=Computers`
are containers. `OU=Domain Controllers` is an organisational unit. Group Policy can only be
linked to an OU, a site, or the domain root. Anything sitting in a default container is
therefore outside the reach of any policy written for it. This is the mechanical reason real
domains build their own OU tree rather than using the defaults.

**GPO objects and GPO links are separate.** Creating a GPO and applying it are two different
operations. A GPO can exist while linked nowhere, and the same GPO can be linked to several
containers at once. That separation is what lets one audit baseline cover both the tier
structure and the Domain Controllers OU without duplicating any settings.

**Link order decides precedence.** Where several GPOs are linked to the same container, the
lower link order number wins. Processing runs from the highest number down, so link order 1
is applied last and overwrites what came before it.

**Windows carries two audit systems.** The legacy one has nine broad categories. The advanced
one has around sixty subcategories and is what all current guidance assumes. They conflict,
and the resolution is a Security Option called "Audit: Force audit policy subcategory
settings to override audit policy category settings". Without it, a legacy setting from
another GPO can silently override your advanced subcategories, and nothing anywhere reports
an error.

**A service principal name makes an account Kerberoastable.** Any authenticated domain user
can request a service ticket for an account with an SPN, and the ticket is encrypted with a
key derived from that account's password. The attacker takes it away and cracks it offline.
No privileged access is needed to start and no failed logons are generated. This is MITRE
ATT&CK T1558.003, and it is one of the more common real-world AD attack paths.

**RID allocation tells you where an account came from.** Built-in principals use fixed
relative identifiers: 500 for Administrator, 501 for Guest, 502 for krbtgt. The first account
created by a person or an installer gets RID 1000. Reading the tail of a SID is therefore
informative.

**PowerShell reads its logging settings once, at session start.** A policy applied to a
running session has no effect until a new session begins. This matters more than it sounds
like it should, as section 6.2 describes.

---

## 4. Design decisions

### 4.1 Tiered OU structure rather than object type

Two models were considered. Organising by object type (Users, Computers, Groups) is the usual
tutorial layout. A tiered model separates Tier 0 (domain controllers and forest-level
identity), Tier 1 (member servers) and Tier 2 (workstations and standard users).

**Decision: tiered.**

The object-type layout records what an object is. It holds nothing about what an object is
allowed to reach, so there is no structural concept of a privilege boundary and nothing to
alert on when one is crossed.

In a tiered model the boundary lives in the directory. "A Tier 2 account authenticated to a
Tier 0 asset" becomes a rule you can write, and it is high fidelity, because in a correctly
administered domain it should not happen at all. That detection cannot be expressed under the
object-type layout at any level of effort, because the underlying data is not there.

It also gives Phase 4 something coherent to simulate. Lateral movement and privilege
escalation are, in tier terms, movement across boundaries. That turns a list of Atomic Red
Team techniques into a scenario rather than a set of isolated events.

Final structure, 14 OUs:

```
lab.local
├── Domain Controllers          (default OU, holds DC01)
└── LAB
    ├── Tier0
    │   ├── Accounts
    │   ├── Servers
    │   └── Groups
    ├── Tier1
    │   ├── Accounts
    │   ├── Servers
    │   ├── Groups
    │   └── ServiceAccounts
    └── Tier2
        ├── Accounts
        ├── Workstations
        └── Groups
```

Tier 1 is empty at the moment. The Wazuh manager is Linux and will not be domain joined, and
the attacker box certainly will not be. It was created anyway, because an empty OU costs
nothing and retrofitting structure later is worse than having it complete from the start.

Every OU was created with `-ProtectedFromAccidentalDeletion`, which sets a Deny ACE for Delete
on Everyone. Deleting an OU takes everything inside it, and the AD Recycle Bin is not enabled
by default, so this is standard practice. The cost is that the flag has to be cleared before
an OU can be removed, which is mildly irritating and entirely correct.

### 4.2 Redirecting the default containers

New computer objects land in `CN=Computers` and new user objects in `CN=Users` unless the
domain is told otherwise. Left alone, the client joined in Milestone 5 would appear outside
the tier structure and receive none of the policy written for it.

```powershell
redircmp "OU=Workstations,OU=Tier2,OU=LAB,DC=lab,DC=local"
redirusr "OU=Accounts,OU=Tier2,OU=LAB,DC=lab,DC=local"
```

This is a domain-wide setting with a real consequence. Every future domain join now lands in
Tier 2 by default. That is right for a workstation and wrong for a server, so servers will
need moving deliberately after joining. Recorded here so it is a known behaviour rather than a
surprise in Milestone 7.

Redirection affects newly created objects only. Administrator, Guest and krbtgt stay in
`CN=Users`, which is correct. Moving krbtgt in particular is a bad idea.

### 4.3 New GPOs rather than editing the defaults

**Decision: create purpose-named GPOs and leave both defaults untouched.**

The two default GPOs are special objects. They carry the domain password policy, account
lockout and Kerberos settings, and they are referenced by GUID in places outside
administrative control. Layering custom settings into them causes three problems:

- `dcgpofix` restores the defaults to factory state and takes any custom settings with it, so
  there is no clean rollback
- Nothing distinguishes settings you added from settings Microsoft shipped, which matters when
  reviewing a 200-setting policy months later
- Default Domain Policy applies to the whole domain and cannot be scoped, which defeats the
  point of having built a tier structure

Named GPOs linked at the right level is what a real environment looks like, and "why did you
not just edit the Default Domain Policy" is a fair question with a good answer.

Two GPOs were created:

| GPO | Purpose |
|---|---|
| `LAB-Audit-Baseline` | Advanced audit subcategories, subcategory override, command line in process creation |
| `LAB-PowerShell-Logging` | Script block logging, module logging, transcription |

### 4.4 Linking to Domain Controllers as well as LAB

`OU=Domain Controllers` sits outside `OU=LAB`, so linking to LAB alone would leave DC01
covered by nothing.

That would be a serious gap, because the events most worth having are generated on the domain
controller. Kerberos ticket requests (4768, 4769) are logged by the KDC, which is the DC.
Account management events (4720, 4728, 4732) are logged where the directory change happens,
which is the DC. The Kerberoasting detection planned for Milestone 14 depends entirely on
4769 events, and those exist nowhere else.

**Decision: link both GPOs to `OU=LAB` and to `OU=Domain Controllers`.**

Linking once at the domain root would also cover the DC, but it would apply to anything ever
added to the domain regardless of where it sits. Two deliberate links beat one blanket one.

### 4.5 PowerShell logging scope, corrected

This was initially planned as a Tier 2 workstation policy, and that scope was wrong.

Script block logging is not workstation specific. Event 4104 captures deobfuscated script
content, and an attacker who reaches a domain controller will run PowerShell on it. Scoping
the policy to Tier 2 would have left the most critical host in the forest blind to exactly the
activity most worth seeing.

Renamed from `LAB-Tier2-Workstation-Logging` to `LAB-PowerShell-Logging` and linked to both
OUs alongside the audit baseline.

### 4.6 Which audit subcategories, and why

Nineteen subcategories enabled. The reasoning is volume against detection value, and what was
left off matters as much as what was turned on.

| Category | Subcategory | Setting | Key events |
|---|---|---|---|
| Account Logon | Credential Validation | S+F | 4776 |
| Account Logon | Kerberos Authentication Service | S+F | 4768 |
| Account Logon | Kerberos Service Ticket Operations | S+F | 4769, Kerberoasting |
| Account Management | User Account Management | S+F | 4720, 4722, 4725, 4726 |
| Account Management | Security Group Management | S+F | 4728, 4732, 4756 |
| Account Management | Computer Account Management | S+F | 4741, 4743 |
| Detailed Tracking | Process Creation | S | 4688 |
| Detailed Tracking | Process Termination | S | 4689 |
| Logon/Logoff | Logon | S+F | 4624, 4625 |
| Logon/Logoff | Logoff | S | 4634 |
| Logon/Logoff | Special Logon | S | 4672 |
| Logon/Logoff | Account Lockout | S+F | 4740 |
| Object Access | File Share | S+F | 5140 |
| Object Access | Detailed File Share | F only | 5145 |
| Policy Change | Audit Policy Change | S+F | 4719 |
| Policy Change | Authentication Policy Change | S | 4713, 4717 |
| Privilege Use | Sensitive Privilege Use | S+F | 4673, 4674 |
| System | Security State Change | S | 4608 |
| System | System Integrity | S+F | 4612, 4616 |

Process Creation was initially set to Success and Failure, then changed to Success only. 4688
is already the highest-volume event on any Windows host, since it fires for every process
launched by every user. A process creation failure means a CreateProcess call that did not
complete, which is high volume with almost no detection value. Roughly doubling the busiest
event stream for that return is not a good trade.

Deliberately left off:

- **Directory Service Access and Changes.** Very high volume on a DC, and of limited value
  until there is a specific object being watched.
- **Registry and File System.** Enormous volume without targeted SACLs in place first.
- **Detailed File Share on Success.** One event per file access. Failure only retains the
  useful signal without the flood.
- **Filtering Platform Connection and Packet Drop.** Firewall-level volume, better handled by
  Sysmon Event ID 3 in Milestone 6.

Tuning down from noise is harder than tuning up from silence, which is the general principle
behind all of the above.

### 4.7 Command line in process creation events

4688 fires without it, but the field showing what was actually invoked is off by default. A
4688 without a command line tells you `powershell.exe` started. With it you get the encoded
command, the download cradle, the arguments. That difference is most of why 4688 is useful.

**Decision: enabled.**

The trade-off is real and worth stating. Command lines sometimes contain credentials, for
example a script invoked with a password as an argument, and that password then sits in the
Security log where anyone who can read the log can read it. In production this is a
conversation with whoever owns the risk. In an isolated lab the detection value wins.

### 4.8 Account lockout threshold

`LockoutThreshold` is 0 in the default domain policy. Lockout is disabled and failed password
attempts are unlimited.

**Decision: left at 0.**

The consequence is specific and needs recording. With lockout disabled, a password spray or
brute force in Milestone 14 produces a stream of 4625 failed logons and no 4740 lockout events
at all. Detection logic will therefore have to be threshold based, counting 4625 events for a
given account or source IP within a time window, rather than keying on a single high-fidelity
4740.

That is the harder rule to write and the more realistic one. It also avoids locking out the
accounts being tested with, which would make repeated attack simulation tedious.

If 4740 events are wanted later, a threshold can be set without disturbing anything else.

### 4.9 PowerShell transcription

Transcription is a different kind of source from script block and module logging. Those two
write to the PowerShell Operational event log. Transcription writes plain text files to disk.
Three consequences:

- Wazuh reads the event log by default, so Milestone 8 needs explicit file monitoring against
  `C:\PSTranscripts` or the transcripts accumulate unread
- There is no built-in rotation or cleanup. PowerShell writes one file per session and never
  removes old ones, so disk usage needs watching
- Transcripts capture output as well as input. Anything a session printed to the console, a
  token, a config file, a credential, is in the file

The third of those turned into a finding, in section 6.3.

---

## 5. Implementation

### 5.1 OU structure

```powershell
$domain = "DC=lab,DC=local"
New-ADOrganizationalUnit -Name "LAB" -Path $domain -ProtectedFromAccidentalDeletion $true
$lab = "OU=LAB,$domain"

foreach ($tier in "Tier0","Tier1","Tier2") {
    New-ADOrganizationalUnit -Name $tier -Path $lab -ProtectedFromAccidentalDeletion $true
}
foreach ($sub in "Accounts","Servers","Groups") {
    New-ADOrganizationalUnit -Name $sub -Path "OU=Tier0,$lab" -ProtectedFromAccidentalDeletion $true
}
foreach ($sub in "Accounts","Servers","Groups","ServiceAccounts") {
    New-ADOrganizationalUnit -Name $sub -Path "OU=Tier1,$lab" -ProtectedFromAccidentalDeletion $true
}
foreach ($sub in "Accounts","Workstations","Groups") {
    New-ADOrganizationalUnit -Name $sub -Path "OU=Tier2,$lab" -ProtectedFromAccidentalDeletion $true
}

redircmp "OU=Workstations,OU=Tier2,$lab"
redirusr "OU=Accounts,OU=Tier2,$lab"
```

### 5.2 Accounts and groups

| Account | Location | Purpose |
|---|---|---|
| `adm.miran` | Tier0/Accounts | Named Domain Admin, separate from daily use |
| `j.smith` | Tier2/Accounts | Standard user, Finance |
| `r.patel` | Tier2/Accounts | Standard user, Engineering |
| `helpdesk1` | Tier2/Accounts | Standard user, IT Support |
| `svc.backup` | Tier1/ServiceAccounts | Service account with SPN, Kerberoast target |

| Group | Scope | Location | Members |
|---|---|---|---|
| `Tier0-Admins` | Global | Tier0/Groups | `adm.miran` |
| `Tier1-ServerOps` | Global | Tier1/Groups | empty, no Tier 1 hosts yet |
| `Tier2-Helpdesk` | Global | Tier2/Groups | `helpdesk1` |

A named admin account rather than shared use of the built-in Administrator means Event 4672
carries a human identity, which matters when attributing activity in Phase 4.

`svc.backup` was created with `MSSQLSvc/backup.lab.local:1433` and `PasswordNeverExpires`,
making it Kerberoastable by design. The password was chosen to be crackable in minutes rather
than seconds. A trivial password would make the Milestone 14 exercise prove nothing except
that short dictionary words are weak, when the point is to test whether the detection fires.

### 5.3 Audit baseline GPO

Created `LAB-Audit-Baseline`. The first thing configured was the subcategory override, before
any audit subcategory at all:

```
Computer Configuration > Policies > Windows Settings > Security Settings
  > Local Policies > Security Options
  > Audit: Force audit policy subcategory settings (Windows Vista or later)
    to override audit policy category settings = Enabled
```

Then the nineteen subcategories from section 4.6, then:

```
Computer Configuration > Policies > Administrative Templates
  > System > Audit Process Creation
  > Include command line in process creation events = Enabled
```

Linked to `OU=LAB` and `OU=Domain Controllers`.

### 5.4 PowerShell logging GPO

Created `LAB-PowerShell-Logging`.

```
Computer Configuration > Policies > Administrative Templates
  > Windows Components > Windows PowerShell
```

| Setting | State | Notes |
|---|---|---|
| Turn on PowerShell Script Block Logging | Enabled | Invocation start/stop left off, it roughly triples volume for marginal value |
| Turn on Module Logging | Enabled | Module names set to `*` |
| Turn on PowerShell Transcription | Enabled | Output directory `C:\PSTranscripts` |

Linked to `OU=LAB` and `OU=Domain Controllers`.

---

## 6. Findings

### 6.1 Unexplained account holding Builtin\Administrators

While reviewing `CN=Users` in ADUC, an account named `mine` appeared alongside the expected
built-ins. It was not one of the defaults.

```powershell
Get-ADUser -Identity "mine" -Properties whenCreated,PasswordLastSet,adminCount,MemberOf,userAccountControl
```

| Property | Value |
|---|---|
| Enabled | True |
| MemberOf | Builtin\Users, **Builtin\Administrators** |
| LastLogonDate | never |
| adminCount | 1 |
| userAccountControl | 512, NORMAL_ACCOUNT with no flags set |
| SID | ends in `-1000` |
| whenCreated | 8 September 2026, 18:48 |
| PasswordLastSet | 1 August 2026, 00:24 |

Builtin\Administrators on a domain controller is full administrative control of that DC, and
on the first DC in a forest that is effectively domain wide. An enabled account with that
membership, no description and no logon history is the shape of a persistence backdoor,
because it sits quietly until needed and an account that is simply present rarely gets
questioned.

**Attribution.** Two details identify it. The SID ending in RID 1000 means it was the first
non-builtin principal created in this environment. The password predating the object by five
weeks is the signature of a local account being converted during AD DS promotion: the account
existed on the standalone server from the 1 August install session, kept its password, and
received a new creation timestamp when the directory object was minted on 8 September. That is
the same mechanism that turned the local Administrator into `LAB\Administrator`, recorded in
Milestone 3 section 5.5.

So it was the account created at Windows Setup, which inherited local Administrators
membership and carried it into the domain.

**Remediation**, in this order:

```powershell
Remove-ADGroupMember -Identity "Administrators" -Members "mine" -Confirm:$false
Disable-ADAccount -Identity "mine"
Get-ADUser mine -Properties MemberOf,Enabled | Format-List Name,Enabled,MemberOf
Remove-ADUser -Identity "mine" -Confirm:$false
```

Privilege removed first, then disabled, then verified, then deleted. Disabling before deleting
is standard incident practice. It removes the account's usability while preserving the object
for investigation, and the verification step in the middle confirms the privilege removal
actually took before the evidence is destroyed.

**Detection implication.** Privileged group membership changes are Events 4728, 4732 and 4756.
Monitoring them is now a concrete Phase 3 rule with a concrete reason behind it.

Worth knowing as a follow-on: `adminCount` does not clear itself, and AdminSDHolder replaces
inherited ACLs on protected objects with a fixed set. Orphaned accounts with `adminCount: 1`
therefore carry hardened ACLs and a marker saying they were once privileged, long after the
privilege has gone. That is a standard AD hygiene audit item.

The account was found because the tier structure made an object sitting outside it visible. In
a domain of four objects that is trivial. The argument for the structure is that it
generalises to a domain of four thousand.

### 6.2 Script block logging appeared to work and did not

After configuring `LAB-PowerShell-Logging` and running `gpupdate /force`, a test command was
run and the PowerShell Operational log queried for Event 4104. Events came back, which looked
like confirmation.

It was not. The timestamps were 17:30 that day and 20 September, while the test ran at 19:15.
The events came from Windows' built-in troubleshooting framework
(`SDIAG_...\CL_Utility.ps1`), not from the test command. Script block logging was not working.

This is the same failure pattern as the `dcdiag` root hints result in Milestone 3 section 7.6:
output that looks like confirmation while actually answering a different question. "Events of
this type exist" and "my configuration produced these events" are separate claims, and only
the second one was being tested.

**Diagnosis.**

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
```

Returned `EnableScriptBlockLogging : 1`, so the policy had applied correctly to the machine.
`Get-GPInheritance` confirmed the GPO was linked and inherited by Domain Controllers. Both
checks passed, so the configuration was not the problem.

**Cause.** PowerShell reads the script block logging setting once, when a session starts. The
session being tested in had been opened before the policy applied, so it would never produce
4104 events no matter what the configuration said.

**Fix.** Close the session, open a new one, retest. Eight 4104 events inside a five-minute
window, including the test command captured verbatim.

Two habits worth carrying forward. Bound every event log query with a time window, using
`StartTime=(Get-Date).AddMinutes(-5)` or similar, both to avoid a wall of output and because
an unbounded query invites exactly this mistake. And when verifying policy, check the machine
registry rather than the GPO report. The report states intent, the registry states outcome.

### 6.3 Transcripts readable by every user

After confirming transcription was writing files, the directory ACL on `C:\PSTranscripts` was
checked.

```
BUILTIN\Administrators    FullControl
NT AUTHORITY\SYSTEM       FullControl
BUILTIN\Users             ReadAndExecute, Synchronize, AppendData, CreateFiles
CREATOR OWNER             GENERIC_ALL, inherit only
```

Any authenticated user on the machine could read every transcript, including transcripts of
Domain Admin sessions. Transcripts capture console output as well as input, so anything a
privileged session printed to screen was readable by an unprivileged user.

This is the inherited default from `C:\` rather than a misconfiguration introduced here, but
it is a real exposure and enabling a logging feature without checking who can read its output
is how that kind of gap persists.

```powershell
icacls C:\PSTranscripts /inheritance:d
icacls C:\PSTranscripts /remove:g "BUILTIN\Users"
```

Inheritance broken first so the parent ACL stops reapplying, then the Users grant removed.
Administrators and SYSTEM keep FullControl.

**Trade-off.** Removing the Users grant also removes write access, so non-administrative
PowerShell sessions can no longer write transcripts. That loses coverage of exactly the
low-privilege activity most worth watching. Microsoft's answer to this tension is a write-only
central file share rather than a local directory. For a single-host lab, locking the directory
down is the right call, but the gap needs testing explicitly in Milestone 5 once a standard
user session exists on a domain-joined client. A logging control that silently covers only
privileged users is worse than no control, because it looks like coverage.

### 6.4 `New-ADUser` is not atomic

Creating `svc.backup` failed with a password complexity error. A retry reported that the
account already existed.

Inspection showed the object had been created with the correct OU, SPN, display name and
`PasswordNeverExpires`, but with no password set and therefore disabled. The cmdlet creates
the object first and applies attributes afterwards, so a failure partway through leaves a
half-configured account behind.

Patched in place rather than deleted and recreated:

```powershell
Set-ADAccountPassword -Identity "svc.backup" -Reset -NewPassword $svcpw
Enable-ADAccount -Identity "svc.backup"
```

The original complexity failure is worth understanding on its own. AD rejects a password
containing the account's `sAMAccountName`, or any token of three or more characters from the
display name, split on spaces, periods, dashes, underscores and commas. For this account the
forbidden tokens were `svc`, `backup`, `Backup`, `Service` and `Account`. The same password had
been accepted for four other accounts minutes earlier. The rule is per account, not global,
which is why bulk creation with a shared initial password fails unpredictably rather than
consistently.

### 6.5 A partial rename left an account inconsistent

Renaming the Tier 0 admin account required two operations. `Rename-ADObject` changed the CN and
succeeded. `Set-ADUser` should have changed `sAMAccountName`, `userPrincipalName` and
`displayName`, and did not apply.

The result was an account whose CN read `adm.miran` while its SAM and UPN still read
`adm.omkar`. Both resolve, so nothing appeared broken.

It matters for correlation. Windows Security events log the `sAMAccountName`, LDAP queries
return the CN, and Kerberos uses the UPN. An account answering to two names across different
telemetry sources makes correlation harder. This is a small instance of a common problem in
directories maintained inconsistently over time, and it is the kind of thing that turns a
straightforward investigation into a confusing one.

Corrected and verified so all four attributes agree.

---

## 7. Validation

### 7.1 OU structure

```powershell
Get-ADOrganizationalUnit -Filter * -SearchBase $lab |
  Select-Object -ExpandProperty DistinguishedName | Sort-Object
```

Fourteen OUs returned, matching the intended structure.

### 7.2 Container redirection

```powershell
Get-ADDomain | Select-Object ComputersContainer,UsersContainer
```

| Property | Value |
|---|---|
| ComputersContainer | `OU=Workstations,OU=Tier2,OU=LAB,DC=lab,DC=local` |
| UsersContainer | `OU=Accounts,OU=Tier2,OU=LAB,DC=lab,DC=local` |

Verified at the directory level rather than trusting the "Redirection was successful" message.

### 7.3 Accounts and groups

```powershell
Get-ADUser -Filter * -SearchBase $lab -Properties Department,ServicePrincipalName,Enabled
Get-ADGroup -Filter * -SearchBase $lab
Get-ADGroupMember "Domain Admins"
```

Five users, all enabled, SPN present on `svc.backup`. Three Global groups. Domain Admins
contains Administrator and `adm.miran`.

### 7.4 Password policy baseline

```powershell
Get-ADDefaultDomainPasswordPolicy
```

| Setting | Value |
|---|---|
| ComplexityEnabled | True |
| MinPasswordLength | 7 |
| MaxPasswordAge | 42 days |
| MinPasswordAge | 1 day |
| PasswordHistoryCount | 24 |
| LockoutThreshold | 0, see section 4.8 |
| LockoutDuration | 10 minutes |
| LockoutObservationWindow | 10 minutes |

### 7.5 GPO application

```powershell
gpupdate /force
gpresult /r /scope:computer
```

Applied Group Policy Objects on DC01: `Default Domain Controllers Policy`,
`LAB-Audit-Baseline`, `Default Domain Policy`.

Link order on `OU=Domain Controllers` puts `Default Domain Controllers Policy` at 1 and
`LAB-Audit-Baseline` at 2, which means the default has higher precedence. The audit baseline
still wins on audit settings, because of the subcategory override configured in section 5.3.
The default GPO defines legacy category settings while the baseline defines advanced
subcategories, and with the override enabled the subcategories take effect regardless of link
order. This is exactly why that setting is configured first rather than last.

### 7.6 Effective audit policy

```powershell
auditpol /get /category:*
```

All nineteen subcategories reported as configured, including Process Creation at Success only.
This is the authoritative check. `gpresult` reports which GPOs applied, `auditpol` reports what
the operating system is actually doing.

### 7.7 Live event verification

Process creation with command line:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 1 |
  Select-Object -ExpandProperty Message
```

Returned a 4688 including `Process Command Line: C:\WINDOWS\system32\svchost.exe -k
LocalService -p -s CaptureService`. The field is present and populated, confirming the
Administrative Template applied.

Three fields in that event are the ones Phase 3 rules will key on. Creator Subject S-1-5-18 is
SYSTEM. Creator Process Name gives parent and child lineage, which is what makes `winword.exe`
spawning `powershell.exe` suspicious when neither process is suspicious alone. Token Elevation
Type indicates the privilege level of the new process.

Account management:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4726} -MaxEvents 6
```

Matched 4720 and 4726 pairs from a deliberate create and delete test. Note that 4720 events
from 20 September appear without matching 4726s. Those are the accounts created before the
audit policy existed. Logging is not retroactive, and a baseline only covers what happens after
it is set.

Script block logging, after opening a new session:

```powershell
Write-Host "audit test 4104 second attempt"
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddMinutes(-5)}
```

Eight events inside the window, including the test command captured verbatim with a ScriptBlock
ID and an empty Path, which is correct for an interactive command rather than a script file.

### 7.8 Structured field extraction

```powershell
$e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 1
$x = [xml]$e.ToXml()
$x.Event.EventData.Data | Where-Object Name -in 'SubjectUserName','NewProcessName','ParentProcessName','CommandLine'
```

Every Windows event carries structured XML beneath the rendered message string. Detection logic
in Phase 3, and Wazuh decoders in Phase 2, operate on those named fields rather than on text
inside a message blob. Worth establishing the habit now rather than later.

### 7.9 Snapshot

`M4-complete` taken after validation.

---

## 8. Evidence

| # | File | Shows |
|---|---|---|
| 4.1 | `01-aduc-default-containers.png` | Clean `lab.local`, Type column showing Container against Organizational Unit |
| 4.2 | `02-ou-tree-aduc.png` | Full tier structure expanded in ADUC |
| 4.3 | `03-get-adorganizationalunit.png` | Fourteen OUs listed, plus `redircmp` and `redirusr` output |
| 4.4 | `04-container-redirection-verified.png` | `Get-ADDomain` showing both containers pointing into Tier 2 |
| 4.5 | `05-mine-account-in-aduc.png` | The `mine` account visible in `CN=Users` |
| 4.6 | `06-mine-account-properties.png` | MemberOf including Builtin\Administrators, adminCount, RID 1000, whenCreated against PasswordLastSet |
| 4.7 | `07-mine-account-remediation.png` | Remove from group, disable, verify, delete sequence |
| 4.8 | `08-password-complexity-failure.png` | `New-ADUser` rejecting the `svc.backup` password |
| 4.9 | `09-svc-backup-final-state.png` | Enabled, SPN registered, PasswordLastSet populated |
| 4.10 | `10-accounts-groups-verified.png` | Five users, three groups, Domain Admins membership |
| 4.11 | `11-password-policy-baseline.png` | `Get-ADDefaultDomainPasswordPolicy` including LockoutThreshold 0 |
| 4.12 | `12-gpo-objects-before.png` | Only the two default GPOs present |
| 4.13 | `13-force-subcategory-override.png` | The override setting Enabled in `LAB-Audit-Baseline` |
| 4.14 | `14-audit-account-logon.png` | Account Logon subcategories |
| 4.15 | `15-audit-account-management.png` | Account Management subcategories |
| 4.16 | `16-audit-detailed-tracking.png` | Process Creation and Termination at Success only |
| 4.17 | `17-audit-logon-logoff.png` | Logon/Logoff subcategories |
| 4.18 | `18-audit-object-access.png` | File Share and Detailed File Share |
| 4.19 | `19-audit-policy-change.png` | Policy Change subcategories |
| 4.20 | `20-audit-privilege-use.png` | Sensitive Privilege Use |
| 4.21 | `21-audit-system.png` | System subcategories |
| 4.22 | `22-command-line-enabled.png` | Include command line in process creation events, Enabled |
| 4.23 | `23-gpo-objects-after.png` | Both custom GPOs alongside the defaults |
| 4.24 | `24-lab-ou-links.png` | GPOs linked to `OU=LAB` |
| 4.25 | `25-domain-controllers-links.png` | GPOs linked to `OU=Domain Controllers`, link order visible |
| 4.26 | `26-gpresult.png` | Applied Group Policy Objects on DC01 |
| 4.27 | `27-auditpol-effective.png` | `auditpol /get /category:*` full output |
| 4.28 | `28-4688-with-command-line.png` | Process Command Line field populated |
| 4.29 | `29-4720-4726-events.png` | Account create and delete events |
| 4.30 | `30-4688-xml-fields.png` | Structured field extraction |
| 4.31 | `31-4104-false-positive.png` | 4104 events predating the policy, the misleading result |
| 4.32 | `32-scriptblock-registry-verified.png` | `EnableScriptBlockLogging : 1` in the machine registry |
| 4.33 | `33-4104-captured.png` | Test command captured verbatim in a 4104 event |
| 4.34 | `34-transcript-acl-before.png` | `BUILTIN\Users` holding ReadAndExecute on `C:\PSTranscripts` |
| 4.35 | `35-transcript-acl-after.png` | Users removed, only SYSTEM and Administrators remain |

---

## 9. Score, 95/100

| Criterion | Weight | Score | Notes |
|---|---|---|---|
| Objective met | 20 | 20 | OU structure, accounts, groups and both GPOs built and applying |
| Design decisions justified | 15 | 15 | Tier model, new GPO against default, dual linking, scope correction, subcategory selection, lockout threshold all reasoned |
| Reproducibility | 10 | 6 | OU and account creation fully scripted. GPO configuration done through the GUI with no scripted or exported equivalent committed |
| Validation depth | 20 | 20 | GPO report, machine registry, `auditpol`, and live events across two log sources |
| Fault diagnosis | 15 | 15 | Unexplained privileged account, false positive 4104 result, transcript ACL exposure, non-atomic cmdlet, partial rename |
| Evidence quality | 10 | 10 | Thirty-five items including three findings captured before and after remediation |
| Rollback discipline | 5 | 4 | Snapshots taken at fragment boundaries, one taken late |
| Operational discipline | 5 | 5 | Wrong GPO opened once and caught before any setting was changed |

**Deductions to carry forward**

1. GPO settings were configured through Group Policy Management with no scripted equivalent.
   Investigate `Backup-GPO` and commit the exported backup, so the audit baseline is
   reproducible rather than a click path described in prose.

---

## 10. Interview questions this milestone answers

- Why can Group Policy not be linked to `CN=Users`?
- What is the difference between a GPO and a GPO link, and why does it matter?
- If two GPOs are linked to the same OU, which one wins?
- Why does Advanced Audit Policy need a subcategory override, and what breaks without it?
- Why would you not organise OUs by object type?
- What makes a service account Kerberoastable, and what does the attack cost an attacker?
- Why is Event 4688 much less useful without command line logging?
- You find an enabled account in Builtin\Administrators that has never logged on. What do you do?
- You enabled a logging policy and the events are there. How do you know your policy produced them?
- What do you lose by enabling PowerShell transcription and then locking down the output directory?

---

## 11. Next, Milestone 5

Windows client build and domain join. The client will land in
`OU=Workstations,OU=Tier2,OU=LAB` automatically because of the redirection in section 4.2, and
will inherit both GPOs on first policy refresh.

Three things to verify there rather than assume:

- That the client actually receives both GPOs, checked with `gpresult` and `auditpol` on the
  client itself rather than on the DC
- That a standard user session produces 4104 and 4103 events, given that the transcript
  directory lockdown in section 6.3 removed write access for `BUILTIN\Users`
- That 4624 logon events on the client and 4768 Kerberos events on the DC can be correlated by
  timestamp, which is the first practical test of the time authority decision made in Milestone
  3 section 4.5
