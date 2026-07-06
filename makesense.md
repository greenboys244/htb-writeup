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

&#x20;
