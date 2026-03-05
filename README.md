# SIEM Log Analysis — Detection Rule Development with Splunk

## Overview
This project documents 5 custom detection rules I developed in Splunk SPL (Search Processing Language) as part of my independent cybersecurity study. Each rule targets a specific MITRE ATT&CK technique and was tested against the publicly available Splunk Boss of the SOC (BOTS) dataset and sample Windows Event Log data.

## Detection Rules Built
| # | Rule Name | MITRE Technique | Data Source |
|---|-----------|----------------|-------------|
| 1 | Brute Force Login Detection | T1110.001 | Windows Event Log 4625 |
| 2 | Encoded PowerShell Execution | T1059.001 / T1027 | Sysmon / Process Creation |
| 3 | Outbound Connection to Malicious IPs | T1071 / T1041 | Firewall / Network Logs |
| 4 | Privileged Account Creation Detection | T1136.001 / T1078 | Windows Event Log 4720/4732 |
| 5 | DNS Tunnelling Detection | T1048.003 | DNS Query Logs |

## Each Rule Includes
- Detection objective and use case explanation
- Full Splunk SPL query (ready to deploy)
- Line-by-line explanation of the query logic
- MITRE ATT&CK technique mapping
- Sample results and findings from BOTS dataset testing
- False positive analysis and tuning recommendations

## Sample Query — Brute Force Detection
```spl
index=windows EventCode=4625
| bucket _time span=5m
| stats count as failed_attempts, values(src_ip) as source_ips by user, _time
| where failed_attempts > 5
| eval risk_score=case(failed_attempts>100,"CRITICAL", failed_attempts>50,"HIGH", true(),"LOW")
| sort -failed_attempts
```

## Tools & Environment
- Splunk Enterprise Free Tier (500MB/day)
- Splunk Boss of the SOC (BOTS) v1 Dataset
- Windows Security Event Logs (Event IDs: 4624, 4625, 4648, 4672, 4688)
- Sysmon v15
- MITRE ATT&CK v14

## Skills Demonstrated
- Splunk SPL query development
- Detection engineering methodology
- Log source understanding (Windows, Sysmon, DNS, Firewall)
- MITRE ATT&CK framework application
- False positive management and rule tuning
- Threat hunting fundamentals

## About Me
**Vishwas M H** | B.Tech Computer Science & Engineering  
Former .NET Full Stack Developer | Transitioning to Cybersecurity  
Actively preparing for MSc Cybersecurity (Ireland, 2026 intake)  
📧 Connect with me on [www.linkedin.com/in/vishwas-m-h-6830bb1b9]
