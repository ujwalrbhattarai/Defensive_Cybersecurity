# Task 5 - Network Traffic Analysis with Wireshark

## Overview
This task demonstrates comprehensive network traffic capture and analysis using Wireshark. The task includes a complete packet capture file (`netcap.pcapng`) and detailed documentation through screenshots showing the entire analysis workflow - from initial interface setup through deep packet inspection to final reporting and conclusions.

## Captured Traffic File
📁 **netcap.pcapng** - Complete network packet capture file containing all captured traffic for analysis

This pcapng file can be opened in Wireshark for detailed inspection and contains all the network packets that were captured during the monitoring session. It serves as the primary data source for the analysis demonstrated in the screenshots below.

---

## Analysis Workflow Documentation

### 1. Initial Packet Capture Setup
![Screenshot 1](Screenshot%202025-11-08%20195016.png)
*Figure 1: Wireshark initial capture interface setup*

The screenshot displays the initial Wireshark interface setup where we configure the capture parameters. This includes selecting the appropriate network interface and setting up capture filters to ensure we collect relevant traffic data. Proper setup is crucial for effective network analysis.

---

### 2. Network Interface Configuration
![Screenshot 2](Screenshot%202025-11-08%20195028.png)
*Figure 2: Network interface selection and configuration*

This view shows the network interface selection screen in Wireshark. Choosing the correct network interface is critical - it determines which network adapter will be used for capturing traffic. The interface typically shows available network adapters including Ethernet, Wi-Fi, and virtual adapters.

---

### 3. Live Packet Capture Session
![Screenshot 3](Screenshot%202025-11-08%20195210.png)
*Figure 3: Active packet capture in progress*

This screenshot captures the live packet capture session in action. The Wireshark interface displays real-time network traffic as packets flow through the network. Each row represents a single packet, showing source/destination addresses, protocols, and packet lengths. The continuous stream demonstrates active network monitoring.

---

### 4. Detailed Packet Inspection
![Screenshot 4](Screenshot%202025-11-08%20195255.png)
*Figure 4: Individual packet analysis*

Here we see detailed packet inspection where a specific packet has been selected for deep analysis. The bottom panes show the packet's hierarchical structure (protocol layers) and the hexadecimal/ASCII dump of the raw packet data. This level of detail reveals headers, payload data, and protocol-specific information essential for forensic analysis.

---

### 5. Protocol Hierarchy Statistics
![Screenshot 5](Screenshot%202025-11-08%20195351.png)
*Figure 5: Protocol breakdown and statistics*

This screenshot demonstrates Wireshark's protocol analysis capabilities. The protocol hierarchy view breaks down all detected network protocols in the capture, showing their relative percentages and packet counts. This helps identify the types of traffic present - HTTP, DNS, TCP, UDP, TLS, etc. - and understand the network's communication patterns.

---

### 6. Display Filter Application
![Screenshot 6](Screenshot%202025-11-08%20195727.png)
*Figure 6: Applying display filters*

Here we see the application of Wireshark display filters. Display filters are powerful tools that allow analysts to narrow down specific types of traffic from the full capture. Filters can target specific protocols (e.g., `http`, `dns`, `tcp`), IP addresses, ports, or complex boolean conditions. This is essential for focusing analysis on relevant packets while excluding noise.

---

### 7. Filtered Packet Results
![Screenshot 7](Screenshot%202025-11-08%20195740.png)
*Figure 7: Viewing filtered traffic*

This screenshot shows the results after applying specific filters. Only packets matching the filter criteria are displayed, making it much easier to analyze particular network behaviors, troubleshoot issues, or identify potential security concerns. The filtered view provides a cleaner, more focused analysis environment.

---

### 8. Deep Packet Content Analysis
![Screenshot 8](Screenshot%202025-11-08%20200255.png)
*Figure 8: Hexadecimal and ASCII packet data*

This view provides deep packet inspection showing both hexadecimal and ASCII representations of packet contents. This granular level of analysis is crucial for identifying malicious payloads, analyzing application-layer protocols, detecting data exfiltration, and understanding the actual content being transmitted across the network.

---

### 9. TCP Stream Reconstruction
![Screenshot 9](Screenshot%202025-11-08%20200311.png)
*Figure 9: Following TCP streams*

This screenshot demonstrates TCP stream analysis using Wireshark's "Follow TCP Stream" feature. This powerful capability reconstructs the complete bidirectional conversation between two endpoints, showing the data exchange in a readable format. This is particularly valuable for analyzing HTTP traffic, identifying transmitted files, or understanding application-layer protocols.

---

### 10. Network Statistics Overview
![Screenshot 10](Screenshot%202025-11-08%20200348.png)
*Figure 10: Statistical analysis and metrics*

Here we see Wireshark's statistics features which provide comprehensive metrics about the captured traffic. This includes conversation statistics (who is talking to whom), endpoint analysis (most active hosts), protocol distribution charts, and bandwidth usage patterns. These statistics help identify network behavior patterns and potential anomalies.

---

### 11. Advanced Analysis Tools
![Screenshot 11](Screenshot%202025-11-08%20200431.png)
*Figure 11: Expert information and advanced features*

This screenshot showcases Wireshark's advanced analysis tools including Expert Information, which automatically identifies potential network issues like retransmissions, connection problems, or unusual patterns. These tools provide deeper insights into network health and help identify security concerns or performance issues.

---

### 12. Export and Reporting
![Screenshot 12](Screenshot%202025-11-08%20200441.png)
*Figure 12: Data export options*

This view demonstrates Wireshark's export capabilities for saving analysis results. Proper documentation and export of findings is essential for reporting and further analysis. Wireshark supports exporting to various formats including CSV, JSON, plain text, and filtered pcap files for sharing specific traffic samples.

---

### 13. Analysis Summary and Conclusions
![Screenshot 13](Screenshot%202025-11-08%20200450.png)
*Figure 13: Final analysis summary*

The final screenshot presents a summary view of the complete analysis. This represents the culmination of the packet capture session, showing key findings and conclusions drawn from examining the network traffic captured in `netcap.pcapng`.

---

## Task Files

This task folder contains the following files:

| File | Description |
|------|-------------|
| **netcap.pcapng** | Complete Wireshark packet capture file with all analyzed network traffic |
| **README.MD** | This documentation file |
| **Screenshot 2025-11-08 195016.png** | Initial setup |
| **Screenshot 2025-11-08 195028.png** | Interface selection |
| **Screenshot 2025-11-08 195210.png** | Live capture |
| **Screenshot 2025-11-08 195255.png** | Packet inspection |
| **Screenshot 2025-11-08 195351.png** | Protocol statistics |
| **Screenshot 2025-11-08 195727.png** | Filter application |
| **Screenshot 2025-11-08 195740.png** | Filtered results |
| **Screenshot 2025-11-08 200255.png** | Deep inspection |
| **Screenshot 2025-11-08 200311.png** | TCP stream |
| **Screenshot 2025-11-08 200348.png** | Statistics |
| **Screenshot 2025-11-08 200431.png** | Advanced tools |
| **Screenshot 2025-11-08 200441.png** | Export options |
| **Screenshot 2025-11-08 200450.png** | Final summary |

---

## Key Skills Demonstrated

This network traffic analysis task showcases the following cybersecurity skills:

### 1. **Packet Capture Setup**
- Proper configuration of Wireshark capture interfaces
- Understanding of network adapters and traffic routing
- Appropriate capture filter setup to collect relevant data

### 2. **Live Traffic Monitoring**
- Real-time observation and analysis of network traffic
- Identification of active protocols and communication patterns
- Recognition of normal vs. suspicious traffic flows

### 3. **Display Filtering**
- Effective use of Wireshark display filters
- Boolean logic for complex filter expressions
- Isolation of specific traffic types for focused analysis

### 4. **Protocol Analysis**
- Deep understanding of network protocol hierarchies (OSI model)
- Analysis of TCP/IP stack behavior
- Application layer protocol identification

### 5. **Deep Packet Inspection**
- Hexadecimal and ASCII analysis of packet payloads
- Header examination across all protocol layers
- Identification of data patterns and content

### 6. **Stream Reconstruction**
- TCP stream following and reassembly
- Understanding of stateful connections
- Application data extraction from packet streams

### 7. **Statistical Analysis**
- Network conversation analysis
- Endpoint traffic profiling
- Protocol distribution assessment
- Bandwidth utilization patterns

### 8. **Forensic Analysis**
- Evidence collection and preservation
- Timeline reconstruction from packet data
- Identification of network anomalies

### 9. **Reporting & Documentation**
- Professional documentation of analysis workflow
- Screenshot evidence collection
- Export of findings for reporting purposes

---

## Tools & Technologies Used

- **Wireshark** - Primary packet capture and analysis tool
- **PCAPNG Format** - Standard packet capture file format
- **Display Filters** - Traffic isolation and analysis
- **Protocol Analyzers** - Built-in protocol dissectors
- **Statistical Tools** - Network metrics and analysis

---

## Analysis Methodology

The analysis followed a structured methodology:

1. **Planning** - Determined what traffic to capture and monitoring duration
2. **Capture** - Set up Wireshark with appropriate interface and filters
3. **Collection** - Captured network traffic to `netcap.pcapng` file
4. **Filtering** - Applied display filters to isolate relevant traffic
5. **Inspection** - Performed deep packet inspection on suspicious/interesting packets
6. **Stream Analysis** - Reconstructed TCP conversations for context
7. **Statistical Review** - Analyzed traffic patterns and distributions
8. **Documentation** - Captured screenshots and documented findings
9. **Reporting** - Compiled comprehensive documentation

---

## Learning Outcomes

Through this task, the following defensive cybersecurity concepts were learned and applied:

✅ **Network Traffic Analysis** - Understanding how data flows across networks  
✅ **Protocol Knowledge** - Deep understanding of TCP/IP and application protocols  
✅ **Wireshark Proficiency** - Mastery of industry-standard packet analysis tool  
✅ **Security Monitoring** - Techniques for detecting anomalous network behavior  
✅ **Forensic Investigation** - Evidence collection and analysis procedures  
✅ **Traffic Filtering** - Efficient isolation of relevant network communications  
✅ **Documentation** - Professional security analysis reporting  

---

## Conclusion

This task successfully demonstrates a complete network traffic analysis workflow using Wireshark. The `netcap.pcapng` file contains the actual captured traffic, while the 13 screenshots provide comprehensive visual documentation of each analysis step - from initial setup through capture, filtering, deep inspection, stream analysis, and statistical review to final conclusions.

The analysis showcases proficiency in using packet analysis tools for defensive cybersecurity purposes, including the ability to capture network traffic, identify protocols, filter relevant data, inspect packet contents, and draw meaningful conclusions from network behavior. These skills are fundamental for network security monitoring, incident response, and threat detection.

**Completed:** November 8, 2025
