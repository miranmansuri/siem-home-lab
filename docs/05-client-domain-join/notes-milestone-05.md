M5 status, 15 Oct evening



DONE and evidenced:

\- Network fix verified: DC01 was on hostonly (VMnet1), moved to VMnet2. Root cause confirmed in vmware.log. WS01 on VMnet2 throughout. Open: how DC01 reached VMnet1 is unknown, logs only reach back 4 Oct (4-log retention). Raise log.keepOld on Tue.

\- Domain join via helpdesk1 (Tier 2), not Tier 0. Reasoning: credentials exposed where typed; WS01 least trusted.

\- Machine account quota set 0, Create Computer objects delegated to Tier2-Helpdesk on OU=Workstations,OU=Tier2,OU=LAB.

\- Proof: WS01 object in Tier2, mS-DS-CreatorSID empty (delegation used, not quota), owner helpdesk1, 4741 names helpdesk1. PrimaryGroupID 515, four benign HOST/RestrictedKrbHost SPNs.



Findings for write-up:

\- Correct in kind, wrong in instance: hostonly matched the design word but was the wrong VMnet.

\- Evidence beat history: notes suspected WS01, ARP evidence pointed at DC01 (correct).

\- Empty output is a result: Tier2-Helpdesk was empty, quota at 0 made it a loud failure not a silent one.

\- Network vs local logon event IDs: helpdesk1 from WS01 logged 4625; j.smith from DC01 logged 4771. Spray detection must cover 4625, not only 4771. (M4 notes already plan 4625-based.)

\- One typo gave four 4771s in one second; count distinct accounts per source over a window, not raw events.



Open follow-ups:

\- j.smith negative test deferred: New-ADComputer and Add-Computer -WhatIf from DC gave artefacts not a verdict. Redo from WS01 as standard user if time.

\- Tier0-Admins and Tier1-ServerOps are empty. Decide memberships (start: does adm.miran belong in Tier0-Admins?). M4 deduction.

\- helpdesk1 password reset to real value after join (LabJoin2026 was test-only).



Tomorrow (Thu 16), remaining M5:

\- Three client-side checks: both GPOs on WS01 via gpresult + auditpol; standard-user session (j.smith, password known) produces 4104 + 4103 given M4 transcript ACL lockdown; 4624 on WS01 vs 4768 on DC01 by timestamp.

\- Then push M4 + M5, confirm repo public, Backup-GPO export.

\- Then M6 Sysmon.

