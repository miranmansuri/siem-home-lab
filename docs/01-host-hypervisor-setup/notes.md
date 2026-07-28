# Milestone 1: Host & Hypervisor Setup - Notes

## What I did


## Issues encountered
1. VBS was silently claiming VT-x - Win32_Processor reported VirtualizationFirmwareEnabled: False
   even though firmware virtualization was genuinely enabled. Diagnosed by cross-checking
   HyperVisorPresent, systeminfo, and Win32_DeviceGuard together rather than trusting one source.
   Fixed by disabling Memory Integrity + Hyper-V-dependent features, confirmed via reboot.
2. Ran disable commands in an elevated PowerShell that defaulted to C:\WINDOWS\system32 - .gitignore
   and README ended up written to the wrong folder, git commands failed with "not a git repository."
3. Two siem-home-lab folders appeared (Documents and Desktop). Resolved by checking git remote -v,
   git log, and Test-Path rather than assuming which one was real - turned out the folder had simply
   been moved, .git history intact.

## Key decisions
- VMware Workstation Pro over VirtualBox:
- VM storage set to C:\VMs instead of default (Documents\Virtual Machines):

## What I'd do differently

