# About

Retrocast is a program for filtering internet traffic on your computer based on time and modifying website layouts. The program uses third-party open-source solutions—WinDivert, Mitmproxy, and Archive.org snapshots (all licenses are located in the licenses.md file).

To filter by time, Retrocast performs the following:
- Decryption (using WinDivert) and scanning of internet packet content (using scanner.dll) to find the material's creation date (if any). If the date is beyond the threshold specified in threshold.txt, the packet is blocked (using Mitmproxy and mitm_addon.py). As a result, you shouldn't see its content in your browser, messenger client, etc.

To modify the appearance of websites to match the time stamp in threshold.txt, Retrocast performs (or attempts to perform):
- Packet injection, deleting the current website layout and replacing it with the archived version from the Snapshots folder (snapshots provided by Archive.org).

Author - Pop-a-ball. Project repo - https://github.com/Pop-a-ball/Retrocast.

# TEST ONLY!

Due to its beta status, this version of the program is NOT INTENDED FOR REGULAR USE OR INTERACTION WITH YOUR PERSONAL TRAFFIC. It is intended FOR TESTING PURPOSES ONLY.

RUN THE PROGRAM ONLY ON VW. DO NOT SCAN SENSITIVE TRAFFIC WITH IT. DO NOT OPEN CHROME WITH A LOGGED-IN GOOGLE ACCOUNT, etc.

The program SAVES OPERATION AND ERROR LOGS (\mitmproxy\mitmdump.out.log, \mitmproxy\mitmdump.err.log) after each startup-shutdown. THESE MAY CONTAIN YOUR TRAFFIC. DO NOT SEND THEM TO ANYONE UNTIL YOU ARE SURE THEY DO NOT CONTAIN YOUR DATA. When you no longer need the logs, REMEMBER TO DELETE THEM.

```
Retrocast/
   Retrocast.exe            — main application (UI only)
   WinDivert.dll            — WinDivert library
   WinDivert64.sys          — WinDivert driver
   windivert_redirect.exe   — WinDivert transparent proxy
   scanner.dll              — Rust scanner for content analysis
   threshold.txt            — config with date threshold
   licenses.md              — licenses for third-party open source solutions
   mitmproxy/               — folder with mitmproxy and the addon script
      mitm_addon.py         — script for blocking by date
      mitmdump.err.log      — error logs (test)
      mitmdump.out.log      — output logs (test)
      snapshot_injector.py  — script for injecting Archive.org snapshots into traffic packets
      whitelist.txt         — list of exceptions for important services (such as Windows updates, etc.)
      Snapshots/            — files located here website snapshots from Archive.org
```

## Requirements

- Windows 10/11 x64
- Test on a virtual machine (due to the beta version of the program)
- Python 3 with mitmproxy

### 1. Installing Python and mitmproxy

- 1.1 Download Python 3.10+ from https://www.python.org/downloads/
- During installation, select: ☑ Add Python to PATH

- 1.2 After installing Python, open PowerShell and install mitmproxy:
```powershell
pip install mitmproxy --upgrade
```

### 2. Preparing the mitmproxy CA certificate

**Important:** A trusted CA certificate is required to intercept your HTTPS.

- 2.1 Run mitmproxy once to generate the CA:
```powershell
mitmproxy
```
- Then, press Q -> Y, or close PowerShell.
- mitmproxy will create the CA in C:\Users\<username>\.mitmproxy -> mitmproxy-ca-cert.cer

- 2.2 Install the certificate in the Windows store (Trusted Root Authorities):
- Press Win+R -> type certlm.msc and press Enter ->
- go to the Trusted Root Certification Authorities folder -> go to Certificates -> right-click -> All Tasks -> Export...
- when you proceed to export the certificate, specify the path to it (C:\Users\<username>\.mitmproxy\mitmproxy-ca-cert.cer)

### 3. Configuring a Proxy in Windows

- Settings -> Network & Internet -> Proxy -> Scroll to Manual Proxy Setup -> Use a Proxy Server - ON -> "127.0.0.1 | 8080" -> Save
- Next, WinDivert automatically redirects 80/443 traffic to 127.0.0.1:8080

### 4. Starting/Stopping the Program

- START:
- Edit the date in threshold.txt to your preferred date (restart the following processes after each edit)

- Run Retrocast.exe as administrator

- Press the buttons in this order:
- 1. Start WinDivert (launch windivert_redirect.exe)
- 2. Start mitmproxy (launch mitmdump with the addon)

- Test in a browser - traffic should be filtered by time

- STOP:
- 1. Stop All (stop both processes)
- 2. Settings -> Network & Internet -> Proxy -> scroll to Manual proxy setup -> Use a proxy server - OFF

### 5. In case the processes don't stop using the buttons

```powershell
Get-Process mitmdump -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process mitmproxy -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process windivert_redirect -ErrorAction SilentlyContinue | Stop-Process -Force
```

### Next, the program should intercept your clients' traffic (browser, etc.), filter it for invalid dates (anything after the date specified in threshold.txt)

### ! In beta, the program saves error logs with your traffic (\mitmproxy\mitmdump.out.log, \mitmproxy\mitmdump.err.log) — don't forget to delete them once you no longer need them.