<#
    Milestone 3 — post-promotion validation
    SIEM Home Lab | https://github.com/miranmansuri/siem-home-lab

    Run as Administrator on DC01 after the promotion reboot, logged in as LAB\Administrator.
    Allow two to three minutes after login before running — services are still settling and
    dcdiag will report spurious failures if run too early.

    Verifies claimed state from the command line rather than trusting the wizard summary.
#>

Write-Host "`n=== 1. Domain and forest identity ===" -ForegroundColor Cyan
Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode, DistinguishedName
Get-ADForest | Select-Object Name, ForestMode, SchemaMaster, DomainNamingMaster
# Expect: lab.local / LAB / Windows2025Domain / DC=lab,DC=local

Write-Host "`n=== 2. FSMO roles ===" -ForegroundColor Cyan
netdom query fsmo
# Expect: all five roles on DC01.lab.local (first DC in a forest holds all of them)

Write-Host "`n=== 3. Core AD services ===" -ForegroundColor Cyan
Get-Service ADWS, DNS, KDC, Netlogon, NTDS
# Expect: all Running. KDC absent or stopped means Kerberos authentication is unavailable.

Write-Host "`n=== 4. Group Policy prerequisites ===" -ForegroundColor Cyan
Get-SmbShare | Where-Object Name -in 'SYSVOL', 'NETLOGON'
# Expect: both present. Absence surfaces later as an unexplained GPO failure.

Write-Host "`n=== 5. DC Locator SRV records ===" -ForegroundColor Cyan
# Pattern: _service._protocol[.role]._msdcs.domain
# This is how an unconfigured client finds a domain to join.
'_ldap._tcp.dc._msdcs.lab.local',   # any domain controller
'_kerberos._tcp.lab.local',         # KDC to authenticate against
'_ldap._tcp.pdc._msdcs.lab.local',  # PDC Emulator specifically
'_ldap._tcp.gc._msdcs.lab.local' |  # global catalog
ForEach-Object {
    Write-Host "`n-- $_" -ForegroundColor DarkGray
    Resolve-DnsName -Name $_ -Type SRV -ErrorAction Continue
}
# Expect: each resolves to dc01.lab.local with an additional A record at 10.10.10.10

Write-Host "`n=== 6. Addressing ===" -ForegroundColor Cyan
Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixLength
Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, ServerAddresses
Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue
# Expect: Ethernet0 = 10.10.10.10/24, resolver = 10.10.10.10, NO default route.
# Note: promotion rewrites the resolver to 127.0.0.1 when it installs the DNS role.
# Functionally equivalent, but reset for consistency with the documented plan:
#   Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 10.10.10.10

Write-Host "`n=== 7. Isolation ===" -ForegroundColor Cyan
Resolve-DnsName google.com -ErrorAction SilentlyContinue
Test-NetConnection 8.8.8.8 -Port 53 -WarningAction SilentlyContinue |
    Select-Object RemoteAddress, RemotePort, PingSucceeded, TcpTestSucceeded
# BOTH MUST FAIL. dcdiag reports root hints "passing" because it validates configuration,
# not reachability (note Ext: n/a in its summary). Verify egress directly.
# An unintended route out changes the risk profile of Atomic Red Team execution in Phase 4.

Write-Host "`n=== 8. Directory health ===" -ForegroundColor Cyan
dcdiag /v
dcdiag /test:DNS /v
# Expect LocatorCheck and Intersite to pass; DNS summary Auth/Basc/Forw/Del/Dyn/RReg PASS,
# Ext n/a. Note that a bare `dcdiag /v` omits the DNS tests — run them explicitly.

Write-Host "`nValidation complete. Snapshot as M3-post-promotion-validated." -ForegroundColor Green
