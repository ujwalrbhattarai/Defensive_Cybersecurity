# 🔐 Task 4: Setup and Use a Firewall on Windows

---

## 📑 Table of Contents
- [Objective](#objective)
- [Tools Used](#tools-used)
- [Steps and Procedure](#steps-and-procedure)
  - [1. Open Windows Firewall](#1-open-windows-firewall)
  - [2. View Current Rules](#2-view-current-rules)
  - [3. Add a Rule to Block Inbound Traffic on Port 23 (Telnet)](#3-add-a-rule-to-block-inbound-traffic-on-port-23-telnet)
  - [4. Test the Rule](#4-test-the-rule)
  - [5. Allow SSH (Port 22)](#5-allow-ssh-port-22)
  - [6. Remove the Test Block Rule](#6-remove-the-test-block-rule)
- [How Firewall Filters Traffic](#how-firewall-filters-traffic)
- [Screenshots](#screenshots)
- [Conclusion](#conclusion)
- [Author](#author)

---

## 🎯 Objective
To configure and test basic firewall rules in **Windows Defender Firewall**, demonstrating how network traffic can be allowed or blocked using port-based filtering.

---

## 🧰 Tools Used
- **Windows Defender Firewall with Advanced Security**
- **Command Prompt (Administrator)**
- **Telnet Client** (enabled for testing)
- **DISM Utility** (for enabling Telnet Client)

---

## ⚙️ Steps and Procedure

### 1️⃣ Open Windows Firewall
Opened the Windows Firewall configuration interface using:
```cmd
wf.msc
````


This launched *Windows Defender Firewall with Advanced Security*, where inbound and outbound rules are managed.

Checked the active profiles via:

```cmd
netsh advfirewall show allprofiles
```

🖼️ *Screenshot 1: Windows Firewall window / Command output here*

---

### 2️⃣ View Current Rules

Listed all existing firewall rules to understand the current configuration.

```cmd
netsh advfirewall firewall show rule name=all
```

🖼️ *Screenshot 2: List of current rules*

---

### 3️⃣ Add a Rule to Block Inbound Traffic on Port 23 (Telnet)

Added a new rule to block Telnet connections (port 23):

```cmd
netsh advfirewall firewall add rule name="Block Telnet" protocol=TCP dir=in localport=23 action=block
```

🖼️ *Screenshot 3: Rule successfully added*

---

### 4️⃣ Test the Rule

When testing, Telnet was not initially recognized.
Enabled it using the DISM feature command:

```cmd
dism /online /Enable-Feature /FeatureName:TelnetClient
```

After installation, tested the rule:

```cmd
telnet localhost 23
```

Result:

```
Connecting to localhost...Could not open connection to the host, on port 23: Connect failed
```

✅ The firewall successfully blocked inbound Telnet traffic.

🖼️ *Screenshot 4: Telnet command and output*

---

### 5️⃣ Allow SSH (Port 22)

To test the opposite scenario, created a rule to allow inbound SSH:

```cmd
netsh advfirewall firewall add rule name="Allow SSH" protocol=TCP dir=in localport=22 action=allow
```

🖼️ *Screenshot 5: SSH allow rule confirmation*

---

### 6️⃣ Remove the Test Block Rule

After completing the test, removed the Telnet block rule to restore the firewall’s default state:

```cmd
netsh advfirewall firewall delete rule name="Block Telnet"
```

🖼️ *Screenshot 6: Rule deletion confirmation*

---

## 🧠 How Firewall Filters Traffic

Windows Firewall filters network traffic based on defined rules.
Each rule specifies parameters like **direction (inbound/outbound)**, **protocol**, **port**, and **action (allow or block)**.
When data packets arrive:

* If they match an *allow* rule → the connection is permitted.
* If they match a *block* rule → the connection is denied.

This mechanism ensures only trusted communications are allowed while unwanted or unsafe connections are blocked.

---

## 📸 Screenshots

> 📂 *All related screenshots (commands, rules, Telnet test results) are included in the `screenshots` folder.*

1. Windows Firewall window
2. Current rule listing
3. Added rule (Block Telnet)
4. Telnet test output
5. Allow SSH rule
6. Deleted rule confirmation

---

## 🏁 Conclusion

Successfully configured and tested Windows Firewall rules using the `netsh advfirewall` command.
Port 23 (Telnet) was blocked, verifying that inbound traffic was denied, while port 22 (SSH) was allowed as expected.
This task provided a clear understanding of how Windows Firewall can be managed via command line and how specific rules affect network access.

