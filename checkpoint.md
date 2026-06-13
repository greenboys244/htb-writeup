# Checkpoint

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

```bash
ip=10.129.12.8

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/connected_tcp.htb $ip



# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/connected_tcp $ip

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/connected_udp.htb $ip
# 123
```
