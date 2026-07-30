```mermaid
graph TB
    subgraph Host["Host machine — Windows 11"]
        VMware[VMware Workstation Pro 26H1]
    end
    subgraph VMnet2["VMnet2 — isolated lab network 10.10.10.0/24"]
        DC["Domain Controller<br/>10.10.10.10<br/>(Milestone 3)"]
        Client["Windows Client<br/>10.10.10.20<br/>(Milestone 5)"]
        Wazuh["Wazuh Manager<br/>10.10.10.30<br/>(Milestone 7)"]
        Attacker["Attacker Box<br/>10.10.10.40<br/>(Milestone 13)"]
    end
    VMware -.host adapter 10.10.10.1.-> VMnet2
    DC ---|domain traffic| Client
    Client -.logs.-> Wazuh
    DC -.logs.-> Wazuh
    Attacker -.attacks.-> Client
```