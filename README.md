# Enterprise SIEM & Adversary Emulation Sandbox

![Platform](https://img.shields.io/badge/Platform-VMware_Workstation_Pro-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-red)
![Framework](https://img.shields.io/badge/Adversary_Emulation-Atomic_Red_Team-orange)
![ATT&CK](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-darkred)
![Status](https://img.shields.io/badge/Status-Active_Lab-brightgreen)

---

## Executive Summary

Engineered an isolated, multi-subnet virtual laboratory to replicate enterprise network boundaries, implement advanced endpoint monitoring telemetry, and validate defensive visibility against scripted real-world threat actors. The environment replicates a realistic corporate network topology — complete with a segmented firewall, Active Directory domain, and dedicated Security Operations Zone — to simulate the conditions a SOC analyst would encounter in production. Endpoint telemetry is provided at the kernel level via Microsoft Sysmon using the SwiftOnSecurity configuration profile, with all host and network events aggregated into a Wazuh SIEM instance for correlation and alerting. Attack scenarios were executed using Red Canary's Atomic Red Team framework, mapped to the MITRE ATT&CK matrix, to verify detection coverage and identify gaps in the defensive stack.

---

## Technical Architecture & Tools

Component | Technology 

Virtualization Engine | VMware Workstation Pro
Network Security | OPNsense Firewall & Router
SIEM / XDR Aggregator | Wazuh SIEM Server
Target Domain Infrastructure | Windows Server 2022 (Active Directory DC) + Windows 10/11 Enterprise Client
Host Telemetry | Microsoft Sysmon with SwiftOnSecurity configuration profile
Adversary Emulation | Red Canary's Atomic Red Team framework and custom commands

---

## Network Topology & Boundary Controls

The lab is divided into three isolated network zones using VMware LAN Segments, with OPNsense enforcing inter-zone traffic policy and acting as the default gateway for all routed subnets. This architecture mirrors a real enterprise environment where the SOC sits on a separate management plane from the assets it monitors.

```
┌───────────────────────────────────────────────────────────────┐
│                        VMware Workstation                     │
│                                                               │
│   ┌──────────────┐     ┌──────────────────┐                   │
│   │  WAN Zone    │     │  OPNsense        │                   │
│   │  VMware NAT  │────▶│  Firewall        │                   │
│   │  192.168.x.x │     │  (Gateway +      │                   │
│   └──────────────┘     │   IDS/IPS)       │                   │
│                        └────────┬─────────┘                   │
│                                 │                             │
│              ┌──────────────────┴──────────────┐              │
│              │                                 │              │
│   ┌──────────▼──────────┐         ┌────────────▼───────────┐  │
│   │  Security Ops Zone  │         │  Target Corporate Zone │  │
│   │  LAN  10.10.10.0/24 │         │  OPT1  10.10.20.0/24   │  │
│   │                     │         │                        │  │
│   │  ┌───────────────┐  │         │  ┌──────────────────┐  │  │
│   │  │ Wazuh Server  │  │         │  │ Windows Server   │  │  │
│   │  │ 10.10.10.151  │  │         │  │ (AD DC)          │  │  │
│   │  └───────────────┘  │         │  │ 10.10.20.100     │  │  │
│   │                     │         │  └──────────────────┘  │  │
│   └─────────────────────┘         │  ┌──────────────────┐  │  │
│                                   │  │ Windows 11       │  │  │
│                                   │  │ Enterprise Client│  │  │
│                                   │  │ 10.10.20.150     │  │  │
│                                   │  └──────────────────┘  │  │
│                                   └────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

**Zone breakdown:**

- **WAN Zone** — VMware NAT (`192.168.x.x`). Provides outbound internet access; no direct inbound routes to internal zones.
- **Security Operations Zone (LAN) — `10.10.10.0/24`** — Hosts the Wazuh manager instance. Firewalled from the target zone; receives only agent-initiated encrypted log streams on port 1514/1515.
- **Target Corporate Zone (OPT1) — `10.10.20.0/24`** — Hosts the Active Directory domain controller and endpoint clients. Wazuh agents are installed on all hosts and forward events to the SecOps zone.

OPNsense firewall rules enforce a default-deny posture between zones, with explicit allow rules only for Wazuh agent communication and DNS resolution. This ensures that a compromised endpoint in the target zone cannot directly access the SIEM.

---

## Adversary Emulation & Logging Verification — The Purple Team Loop

Each test follows the same loop: execute an Atomic Red Team technique on the target host → observe the Sysmon telemetry → verify the Wazuh alert fired with the expected fields. The goal is not just to confirm an alert exists, but to understand *exactly which log field* surfaced the behaviour.

---

### Test 1 — T1070.001: Indicator Removal — Event Log Clearing

**Adversary technique:** Attackers clear Windows event logs post-compromise to remove evidence of lateral movement, credential access, or execution. MITRE ATT&CK maps this to T1070.001 (Indicator Removal on Host: Clear Windows Event Logs).

**Execution method:**
```powershell
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
```

---

### Test 2 — T1547.001: Boot or Logon Autostart — Registry Run Key

**Adversary technique:** Establishing persistence by writing a malicious binary path to the `HKCU\...\Run` registry key. The payload executes automatically on every user logon without requiring elevated privileges.

**Execution method:**
```powershell
Invoke-AutomicTest T1547.001 TestNumbers 1
```

The parent process chain is also visible: `powershell.exe` → `reg.exe`, which provides full execution lineage. A defence analyst can trace the original PowerShell session that spawned the registry write.

**Cleanup:**
```powershell
Invoke-AutomicTest T1547.001 -Cleanup
```

---

### Test 3 — T1053.005: Scheduled Task / Job — Persistence via schtasks.exe

**Adversary technique:** Adversaries abuse the Windows Task Scheduler to establish persistent execution of a malicious payload. By creating a scheduled task that runs at logon, on a time interval, or triggered by a system event, an attacker survives reboots without touching the more heavily monitored registry Run keys. This is a native-binary technique — schtasks.exe ships with every Windows installation — which makes it a reliable and commonly observed persistence mechanism in real intrusions.
Atomic Red Team test: T1053.005 — Atomic Test #1: Scheduled Task Startup Script

**Execution method:**
```powershell
Invoke-AutomicTest T1053.005 TestNumbers 1
```

**Cleanup:**
```powershell
Invoke-AutomicTest T1053.005 -Cleanup
```

---

### Test 4 — T1016 / T1049: Network Discovery — Internal Reconnaissance Burst

**Adversary technique:** After initial access, adversaries perform internal network discovery to map the environment before moving laterally. This tradecraft — sometimes called "living off the land" reconnaissance — uses only built-in Windows binaries (ipconfig, arp, netstat, net, nslookup) so it leaves no dropped tooling for antivirus to detect. MITRE ATT&CK maps the individual commands across T1016 (System Network Configuration Discovery) and T1049 (System Network Connections Discovery).
Atomic Red Team tests:

T1016 — Atomic Test #1: System Network Configuration Discovery
T1049 — Atomic Test #1: System Network Connections Discovery

**Execution method:**
```powershell
Invoke-AutomicTest T1016 -Name TestNumbers 1
Invoke-AutomicTest T1049 -Name TestNumbers 1
```



## Key Engineering Takeaways & Lessons Learned

**Network isolation is a detection multiplier.** Separating the SIEM into its own network zone means an attacker who compromises an endpoint cannot tamper with the logging infrastructure. Log forwarding from the Wazuh agent is outbound-only from the target zone, so no firewall rule exists that would allow an endpoint to reach back and modify the manager. This design choice mirrors best-practice SOC architecture and prevents the common attack of clearing logs *at the collector* rather than just on the host.

**Sysmon changes the game compared to native Windows logging.** Standard Windows event logs capture *what happened* — a process started, a file was created. Sysmon captures *how it happened* — the full command line, the parent process, the network destination, the file hash, and the registry key touched. The difference between investigating `EventID 4688` (process created, no command line by default) and Sysmon `EventID 1` (process created with full command line, hash, and parent) is the difference between a dead-end and a complete attack chain reconstruction. The SwiftOnSecurity configuration profile adds noise filtering on top of this, suppressing high-volume benign events so that the genuinely suspicious activity stands out.

**Atomic Red Team exposes detection blindspots honestly.** Several tests produced *no alert at all* on the first run, which was the most valuable outcome. Absence of an alert for a documented, real-world technique is a concrete blindspot that can be remediated. Running the purple team loop — emulate, observe, tune, re-emulate — is a far more rigorous approach to validating a SIEM deployment than assuming coverage based on a vendor's marketing documentation.

