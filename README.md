# WebStrike-Lab
SOC Analyst Tier 1 Lab. Analyze network traffic using Wireshark to investigate a web server compromise, identify web shell deployment, reverse shell communication, and data exfiltration.

### Category:
Network Forensics
### Tactics: 
Initial Access Execution Persistence Command and Control Exfiltration
### Tool: Wireshark

## Scenerio
A suspicious file was identified on a company web server, raising alarms within the intranet. The Development team flagged the anomaly, suspecting potential malicious activity. To address the issue, the network team captured critical network traffic and prepared a PCAP file for review.
Your task is to analyze the provided PCAP file to uncover how the file appeared and determine the extent of any unauthorized activity.

## Investigation Questions and how I approached them
1. Identifying the geographical origin of the attack facilitates the implementation of geo-blocking measures and the analysis of threat intelligence. From which city did the attack originate?
Solution: To find the geographical origin of the attack, i opened the provided PCAP file and analysed from which IP address the attack came from. The IP address of the attacker was found to be 117.11.88.124
I used https://www.iplocation.net/ip-lookup for ip look up. The search results showed the geographical origin of the attack to be China and city Tianjin.
