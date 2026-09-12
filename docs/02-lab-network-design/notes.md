# Milestone 2: Isolated Lab Network Design - Notes

## What I did
Built a dedicated, fully isolated virtual network for the whole lab and fixed the IP
addressing plan for every machine before any of them existed. Created `VMnet2` as a
host-only network in VMware's Virtual Network Editor, assigned it `10.10.10.0/24`, disabled
its DHCP server so every host gets a deliberate static address, verified the host adapter
from the command line rather than trusting the GUI, and committed an architecture diagram
describing the finished topology.

Nothing in this milestone is visible as a running service. It is the set of constraints
every later milestone operates inside.

## Why isolation is the first design decision

From Milestone 13 this network hosts Atomic Red Team executing real ATT&CK techniques
against a domain-joined Windows client. Before any of that exists, the network it runs on
has to be incapable of reaching anything that matters.

A host-only network satisfies that: VMs can reach each other and the host adapter, and
there is no bridge to the physical network and no NAT path to the internet. There is no
firewall rule to misconfigure and no route to accidentally leave in place — the path simply
does not exist.

The alternative configurations were both rejected:

- **Bridged** puts lab VMs directly onto the physical home network, where an unpatched
  Windows Server and a machine running attack tooling sit alongside real devices.
- **NAT** gives the lab outbound internet access. Tempting for downloading Sysmon, Wazuh
  agents and Atomic Red Team, but it means simulated attack traffic has an egress path, and
  it means lab hosts can resolve and reach real infrastructure.

Tooling gets into the lab through ISO mounts and VMware shared folders instead, which is
slower but keeps the isolation property intact. This is a constraint accepted deliberately,
not an oversight — and Milestone 3 verified it empirically rather than assuming it held
(external DNS resolution fails, `8.8.8.8` is unreachable, no default route exists).

## Key decisions

**`10.10.10.0/24`, not `192.168.0.0/24` or `192.168.1.0/24`.**
Both of those are the default ranges on the majority of consumer routers. Choosing a range
that does not collide with a typical home network means that later, when reading Wazuh
alerts and Sysmon events, any `10.10.10.x` address is unambiguously lab traffic. It also
avoids any chance of the host's routing table having to choose between two identical
subnets. This is a small decision made for the benefit of log readability eight milestones
later.

**DHCP disabled, static addressing throughout.**
VMware's host-only networks run a DHCP server by default. Turned off, for three reasons:
a domain controller must have a fixed address because clients locate it through DNS records
that point at that address; log correlation is far easier when a given IP always means the
same machine; and a DHCP server sitting on the lab network would itself be a log source
generating noise that has nothing to do with the detections being built.

**Addressing plan fixed before any machine was built.**
Assigning addresses up front rather than as each VM appears means the plan can be reasoned
about as a whole, and each later milestone has an unambiguous target rather than a decision
to make under time pressure.

| Host | Static IP | Role | Built in |
|---|---|---|---|
| Hypervisor host (VMnet2 adapter) | 10.10.10.1/24 | Host's bridge into the lab | Milestone 2 |
| Domain Controller | 10.10.10.10/24 | AD DS + DNS | Milestone 3 |
| Windows Client | 10.10.10.20/24 | Domain-joined workstation, Sysmon source | Milestone 5 |
| Wazuh Manager | 10.10.10.30/24 | SIEM — log aggregation, detection rules | Milestone 7 |
| Attacker Box | 10.10.10.40/24 | Atomic Red Team / attack simulation | Milestone 13 |

Addresses are spaced in tens rather than assigned sequentially, leaving room to insert
additional hosts of the same class without renumbering — a second domain controller at
`.11`, a second client at `.21`.

**No default gateway anywhere in the plan.**
There is nothing to route to. Each machine's network configuration omits a gateway entirely,
which makes the isolation design visible in host configuration rather than existing only as
a hypervisor setting. Milestone 3 applied this and confirmed it: `Get-NetRoute` finds no
`0.0.0.0/0` entry on DC01.

## Verification

The Virtual Network Editor reports what it was told to configure. The host adapter was
checked independently:

```powershell
Get-NetIPAddress -AddressFamily IPv4
```

Confirmed the VMnet2 host adapter holding `10.10.10.1/24`. Checking declared state from the
command line rather than accepting a GUI's own report is the habit this lab tries to hold to
throughout — Milestone 3 contains a case where a wizard's summary and the actual system
state diverged.

## Topology

See [`network-diagram.md`](network-diagram.md) for the Mermaid source and
[`architecture-diagram.jpg`](architecture-diagram.jpg) for the rendered diagram.

## Issues encountered

1. VMware's host-only networks enable a DHCP server by default, which is easy to leave
   running because nothing visibly breaks. It would have quietly handed out addresses
   alongside the static plan and created an inconsistency that would only have surfaced
   later as a machine with an unexpected IP.

## What I'd do differently

- Record the reasoning behind the subnet and addressing choices at the time of making them.
  This write-up was expanded after Milestone 3, and reconstructing the rationale afterwards
  is harder and less reliable than capturing it as the decision is made.
- Verify the host adapter address immediately after creating the network rather than at the
  end of the milestone, so a misconfiguration surfaces before anything is built on top of it.

## Carried into Milestone 3

The addressing plan above, the no-gateway rule, and the isolation property — all three were
applied when building DC01 and verified empirically as part of that milestone's validation.
