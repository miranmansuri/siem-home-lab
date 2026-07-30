| Host | Static IP | Role | Built in |
|---|---|---|---|
| Hypervisor host (VMnet2 adapter) | 10.10.10.1/24 | Host's bridge into the lab | Milestone 2 |
| Domain Controller | 10.10.10.10/24 | AD DS + DNS | Milestone 3 |
| Windows Client | 10.10.10.20/24 | Domain-joined workstation, Sysmon source | Milestone 5 |
| Wazuh Manager | 10.10.10.30/24 | SIEM — log aggregation, detection rules | Milestone 7 |
| Attacker Box | 10.10.10.40/24 | Atomic Red Team / attack simulation | Milestone 13 |