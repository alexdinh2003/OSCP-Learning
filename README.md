# OSCP Preparation Journey

## Overview
This repository documents my OSCP preparation journey using hands-on labs, challenge platforms, and note-taking from **Hack The Box (HTB)** and **TryHackMe (THM)**. My goal is to build strong practical penetration testing skills in enumeration, exploitation, privilege escalation, lateral movement, and reporting.

## Goals
- Build a solid OSCP-focused penetration testing foundation
- Improve methodology for attacking standalone and Active Directory environments
- Practice privilege escalation on both Linux and Windows
- Strengthen enumeration and note-taking habits
- Develop time management skills for exam-style scenarios
- Create a repeatable workflow for real-world offensive security engagements

## Platforms Used

### Hack The Box (HTB)
Hack The Box helps me practice realistic penetration testing challenges that require strong enumeration, exploitation, and privilege escalation skills. I use HTB to improve my problem-solving ability and get comfortable with unfamiliar systems.

Focus areas:
- Linux and Windows machine exploitation
- Privilege escalation
- Web application attacks
- Active Directory labs
- Post-exploitation methodology

### TryHackMe (THM)
TryHackMe provides guided and beginner-friendly learning paths that help reinforce core concepts before applying them in harder labs. I use THM to review fundamentals and strengthen weak areas.

Focus areas:
- Penetration testing basics
- Networking and web security
- Windows and Linux fundamentals
- Buffer overflow practice
- Active Directory concepts
- Red team and offensive security paths

## Concepts Practiced

Based on the OSCP-like machines completed, my preparation has covered a wide range of offensive security concepts relevant to the PEN-200 / OSCP exam.

### Enumeration
- Service enumeration with common protocols
- Web enumeration and content discovery
- SMB, LDAP, Kerberos, WinRM, RDP, FTP, SSH, and HTTP/HTTPS enumeration
- User and share enumeration in Windows environments
- Identifying attack surface through versioning, exposed services, and misconfigurations

### Web Exploitation
- File upload vulnerabilities
- Authentication bypass and weak access controls
- Local File Inclusion (LFI) / Remote File Inclusion (RFI)
- Command injection
- SQL injection concepts
- Web app misconfiguration abuse
- CMS and custom web application exploitation
- Credential discovery through web application functionality

### Initial Access
- Exploiting vulnerable web applications
- Credential reuse and password attacks
- Abuse of exposed services and weak configurations
- Leveraging default credentials or disclosed secrets
- Gaining footholds through misconfigured internal services

### Linux Privilege Escalation
- Misconfigured sudo permissions
- Weak file permissions
- Service and binary abuse
- Credential harvesting from files, scripts, and configs
- PATH hijacking and environment abuse
- Kernel and application-based escalation opportunities

### Windows Privilege Escalation
- Service misconfigurations
- Scheduled tasks and startup abuse
- Registry and permission weaknesses
- Stored credentials and configuration file abuse
- Token and privilege misuse
- Abusing insecure service accounts and local misconfigurations

### Active Directory Attacks
- Kerberoasting
- AS-REP Roasting
- Password spraying
- LDAP and SMB-based domain enumeration
- BloodHound-style relationship analysis
- Abuse of delegated privileges and ACL misconfigurations
- Lateral movement through reused or harvested credentials
- Domain privilege escalation through misconfigured accounts or group memberships

### Credential Access
- Password hash extraction
- Reuse of found credentials across services
- Sensitive data discovery in shares, backups, configs, and documents
- Enumeration of hardcoded credentials
- Abuse of service account credentials

### Post-Exploitation
- Lateral movement in Windows environments
- Pivoting concepts between services and accounts
- Access expansion after initial foothold
- Looting sensitive files and credentials
- Identifying privilege relationships for escalation

### OSCP-Relevant Skills Strengthened
- Manual enumeration methodology
- Chaining multiple weaknesses into a full compromise
- Local privilege escalation on both Linux and Windows
- Active Directory attack path identification
- Note-taking and attack path documentation
- Persistence in solving realistic exam-style machines

## Key Learning Themes from Completed Boxes
The machines completed suggest strong exposure to:
- Windows-heavy OSCP-like environments
- Active Directory compromise paths
- Mixed web + system exploitation chains
- Credential-driven attack paths
- Privilege escalation through misconfiguration rather than automation
- Realistic enumeration-first methodology

