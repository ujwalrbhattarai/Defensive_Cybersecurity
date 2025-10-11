# README.md

## Local Network Scan — Summary

**Purpose:** Document the local network reconnaissance I performed using **Nmap**, record findings, and preserve evidence from the session.

**Primary evidence:** `what i did` (session log).
**Supporting evidence:** 4 screenshots in the same folder as this README.

---

## Tools

* Nmap (TCP SYN scan `-sS`, service/version detection `-sV`, OS detection `-O`, aggressive `-A`, output `-oA`).
* PowerShell (commands executed from PowerShell).
* (Optional) Wireshark for packet-capture analysis.

---

## Steps that i completed

1. Installed Nmap and confirmed it runs from PowerShell.
2. Determined local network range (example used: `192.168.1.0/24`).
3. Performed network scan(s) using `nmap -sS 192.168.1.0/24`.
4. Recorded discovered IP addresses and open ports in the session log (`what i did`).
5. Performed targeted scans (examples recorded in the log) including service/version and OS probes.
6. Saved scan output using Nmap output options (e.g., `-oA` produced `.nmap`, `.xml`, `.gnmap` files when used).
7. Collected four screenshots that corroborate the commands and results.

All exact commands, timestamps, and raw output are preserved in the `what i did` file.

---

## Key findings from my log

* Multiple hosts were discovered on the `192.168.1.0/24` network.
* Exposed services were observed in the log include HTTP (80/8008/8443), RTSP (554), SMB (139/445), Telnet (23), and several non-standard/open ports (recorded per-host in the session log).
* A Windows host with SMB and RPC services and several IoT/embedded devices with web/management ports were identified.

Refer to `what i did` for specific host IPs and full port/service listings.

---

## Security Risks - Open Ports Analysis

### Critical Security Risks Identified:

* **Port 23 (Telnet)** - Unencrypted remote access protocol that transmits credentials and data in plaintext, making it vulnerable to eavesdropping and man-in-the-middle attacks.

* **Ports 139/445 (SMB)** - File sharing services that can expose sensitive data if misconfigured. These ports are frequently targeted for:
  - Unauthorized file access
  - Lateral movement in network attacks
  - Ransomware propagation
  - Credential harvesting

* **Port 80/8008/8443 (HTTP/Web Services)** - Web management interfaces that may have:
  - Default or weak authentication
  - Unpatched vulnerabilities
  - Directory traversal weaknesses
  - Cross-site scripting (XSS) vulnerabilities

* **Port 554 (RTSP)** - Real-time streaming protocol often found on IP cameras and media devices, risks include:
  - Unauthorized surveillance access
  - Device hijacking for botnets
  - Privacy violations

### Additional Open Port Risks:
* **Non-standard ports** - Custom services running on unusual ports may indicate:
  - Backdoors or malware
  - Misconfigured services
  - Shadow IT deployments
  - Potential data exfiltration channels

### Mitigation Recommendations:
1. Close unnecessary ports and services
2. Implement network segmentation
3. Use encrypted alternatives (SSH instead of Telnet)
4. Regular security updates and patch management
5. Strong authentication and access controls
6. Network monitoring and intrusion detection

---

## Evidences

* `what i did` — full Nmap/PowerShell session log (canonical evidence).
* Four supporting screenshots (located in the same folder as this README).
* Nmap output files (if `-oA` was used during the session, corresponding `.nmap`, `.xml`, and `.gnmap` files may be present).

---

## Commands (examples present in the session log)

```
nmap -sS 192.168.1.0/24
nmap -sn 192.168.1.0/24
nmap -sS -sV -O -oA myscan 192.168.1.0/24
nmap -A -p- 192.168.1.5
```

---
