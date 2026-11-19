# Network Intrusion Detection System (NIDS) — Project Introduction

## 1. Project Introduction

The Network Intrusion Detection System (NIDS) is a cybersecurity project
designed to monitor network traffic, identify suspicious activities, detect
potential cyberattacks, and generate security alerts.

The system continuously inspects network traffic using **Suricata**, an
open-source intrusion detection engine. When suspicious activity is detected,
the system generates alerts, which are processed using **Python**.

A web-based dashboard provides a visual representation of detected threats,
network activities, and security incidents.

The overall goal is to build a system that helps network administrators
identify and respond to potential security threats before they cause
significant damage.

## 2. Project Objectives

The main objectives are:

1. Monitor network traffic in real time.
2. Detect suspicious and potentially malicious network activities.
3. Configure detection rules to identify different types of attacks.
4. Generate alerts when suspicious activities are identified.
5. Record and analyse detected security incidents.
6. Implement response mechanisms for detected intrusions.
7. Visualise detected attacks using a security dashboard.

## 3. System Process

The system follows this process:

8. **Traffic monitoring:** Suricata monitors network traffic passing through
   the selected network interface.
9. **Traffic inspection:** Suricata examines packets and compares network
   activities against configured detection rules.
10. **Threat detection:** Suspicious activities such as port scanning and
    unauthorised connection attempts are identified.
11. **Alert generation:** Suricata generates alerts when its detection rules
    are triggered.
12. **Log processing:** Python reads and processes the generated security logs.
13. **Incident response:** The system records detected threats and can perform
    controlled response actions, such as blocking confirmed malicious IP
    addresses.
14. **Visualisation:** A Streamlit dashboard displays security alerts, detected
    threats, and network activity statistics.

## 4. Types of Attacks the System Will Detect

We configure detection rules to identify activities such as:

| Attack / Activity | What the system looks for |
|---|---|
| Port scanning | Attempts to discover open network ports |
| Suspicious connections | Unusual or unauthorised connection attempts |
| ICMP scanning | Suspicious ICMP probing activity |
| Brute-force indicators | Repeated authentication attempts where visible |
| Malicious traffic | Traffic matching known detection signatures |
| Suspicious network activity | Unusual patterns identified by configured rules |

> **Note:** Detection depends on the available traffic, visibility, and
> configured rules. The system will not automatically identify every possible
> cyberattack.

## 5. Technologies to be Used

| Technology | Purpose |
|---|---|
| Ubuntu Linux | Operating environment |
| Suricata | Network intrusion detection |
| Python | Log processing and automation |
| Bash | System administration |
| JSON | Security event storage |
| Streamlit | Security dashboard |
| VirtualBox | Isolated testing environment |
| Git and GitHub | Version control and project submission |

## 6. Main Components of the Project

### Network Monitoring Engine
Uses Suricata to monitor and inspect network traffic continuously.

### Intrusion Detection Rules
Contains predefined and custom rules for detecting suspicious network
activities.

### Alert Processing and Response
Uses Python to analyse alerts, record incidents, and implement controlled
security responses.

### Security Dashboard
Displays detected threats, alert counts, suspicious IP addresses, and attack
statistics.

### Documentation and Reporting
Contains project documentation, screenshots, testing results, and source code
for GitHub submission.

## 7. Expected Project Deliverables

At the end of the project, we should have:

- A fully configured Suricata intrusion detection engine.
- Custom network intrusion detection rules.
- A Python-based alert processing system.
- A security incident logging mechanism.
- An automated response mechanism.
- A functional web-based security dashboard.
- Evidence of successful attack simulations and detection.
- A GitHub repository containing the complete source code and documentation.

## 8. Project Development Roadmap

We complete the project in the following order:

| Phase | Description |
|---|---|
| 1 | Environment setup |
| 2 | Suricata installation and configuration |
| 3 | Intrusion detection rules |
| 4 | Python alert processing |
| 5 | Automated response mechanisms |
| 6 | Dashboard development |
| 7 | Testing, documentation and GitHub submission |
