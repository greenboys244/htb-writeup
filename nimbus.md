# Nimbus

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

{% code overflow="wrap" %}
```bash
ip=10.129.15.150

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/nimbus_tcp.htb $ip
# 22/tcp open  ssh
# 80/tcp open  http



# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/nimbus_tcp $ip

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/nimbus_udp.htb $ip
```
{% endcode %}

<mark style="color:blue;">**Step 2**</mark>

**we modify the hosts file**

{% code overflow="wrap" %}
```bash
echo "10.129.15.150 nimbus.htb" | tee -a /etc/hosts
```
{% endcode %}

<mark style="color:blue;">**Step 3**</mark>&#x20;

**We fuzz for Vhosts**

{% code overflow="wrap" %}
```bash
curl -s -I http://$ip -H "HOST: nimbus.htb" | grep "Content-Length:"
# Content-Length: 1922

ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt:FUZZ -u http://nimbus.htb/ -H 'Host:FUZZ.nimbus.htb' -fs 1922,178
# aws
```
{% endcode %}

<mark style="color:blue;">**Step 4**</mark>

**Let's start by discovering the APP**
