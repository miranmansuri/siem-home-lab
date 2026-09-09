<#
    Milestone 3 — AD DS forest promotion
    SIEM Home Lab | https://github.com/miranmansuri/siem-home-lab

    Exported from the AD DS Configuration Wizard via Review Options -> View script,
    retained so the promotion is reproducible without the GUI.

    Target : DC01.lab.local (10.10.10.10/24, VMnet2, isolated)
    Forest : lab.local  (single-domain, functional level Windows Server 2025)

    PREREQUISITES — both are hard requirements, see milestone-03 sections 4.2 and 5.5:
      1. Machine renamed to DC01 BEFORE promotion. Renaming a live DC requires
         netdom computername plus SPN and DNS record changes.
      2. Local Administrator has a password set. Promotion converts this account into
         the first Domain Admin of the forest and refuses to proceed if it is blank.
      3. Static IP assigned and DNS pointed at itself. The DC registers its A and SRV
         records against whatever address it holds at promotion time.
      4. VM snapshot taken. Promotion is not cleanly reversible.

    Prompts interactively for the DSRM (Directory Services Restore Mode) password.
    Record it outside this repository — it is required precisely when domain
    authentication is unavailable.
#>

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

# -CreateDnsDelegation:$false — no authoritative parent zone exists for .local and there
#   is no external DNS infrastructure to delegate from. Expected in an isolated forest.
# -InstallDns:$true — AD DS is unusable without DNS; clients locate DCs via SRV records
#   under _msdcs.lab.local.
# -NoRebootOnCompletion:$false — server reboots itself on completion.
