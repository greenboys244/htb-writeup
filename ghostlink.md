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

