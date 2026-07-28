# Milestone 1: Host & Hypervisor Setup - Notes

## What I did
Installed VMware Workstation Pro 26H1 under Broadcom's free personal-use license (no key
required). Verified hardware virtualization support, resolved a Windows-side conflict where
VBS was silently claiming VT-x, set VM storage to a dedicated C:\VMs folder outside of
OneDrive-synced locations, and initialized the GitHub repo with a .gitignore tuned to keep
VM binaries and secrets out of version control.

## Issues encountered
1. Win32_Processor reported VirtualizationFirmwareEnabled: False even though VT-x was
   genuinely enabled in firmware. Root cause: Windows' own Virtualization-Based Security
   (Memory Integrity / Core Isolation) was already running and had claimed the CPU's
   virtualization extensions, which breaks the check third-party hypervisors rely on.
   Diagnosed by cross-referencing three independent sources (HyperVisorPresent, systeminfo's
   "a hypervisor has been detected" message, and Win32_DeviceGuard) rather than trusting any
   single reading. Fixed by disabling Memory Integrity and the Hyper-V-dependent Windows
   features, confirmed clean after a reboot.
2. Windows 11 Home doesn't ship the full Hyper-V role - attempting to disable it returned
   "Feature name is unknown," which is expected on Home, not an error to chase.
3. Ran the initial repo setup commands in an elevated PowerShell window that had opened at
   C:\WINDOWS\system32 by default. Files were written there instead of the repo folder, and
   git commands failed with "not a git repository" as a result. Fixed by moving the files
   into the correct location.
4. The repo folder ended up relocated from Documents to Desktop, which looked at first like
   two separate duplicated repos. Resolved by checking git remote -v, git log, and Test-Path
   against the old location instead of assuming - confirmed Desktop was the single real copy
   with full history intact.
5. VMware's default VM storage location (Documents\Virtual Machines) sits inside a folder
   OneDrive commonly auto-syncs on Windows 11. Multi-gigabyte VM disk files being written to
   continuously while syncing risks corruption. Moved storage to C:\VMs instead.

## Key decisions
- VMware Workstation Pro over VirtualBox: free for personal use, conceptually closer to
  enterprise tooling (ESXi/vSphere), better positioned for interview relevance.
- VM storage at C:\VMs rather than the default: avoids OneDrive interfering with actively
  written VM disk files.

## What I'd do differently
- Confirm which terminal window and working directory I'm in before running file or git
  commands, especially right after accepting a UAC elevation prompt.
- Verify a command's actual effect (file exists, file has content) instead of assuming
  success just because no error was shown.
