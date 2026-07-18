# Bedside

<figure><img src=".gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

```bash
ip=10.129.49.252

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
