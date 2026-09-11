# Session 13 — Identity and Authentication Management

## `keycloak-lab.sh`

```bash
./keycloak-lab.sh up          # dev mode: no TLS, no persistence, no illusions
./keycloak-lab.sh realm       # realm, public client with PKCE, group, two users
./keycloak-lab.sh endpoints   # the URLs, plus a flow you can watch in devtools
./keycloak-lab.sh review      # the five findings, checked against YOUR realm
./keycloak-lab.sh export
```

It never puts an application in the `master` realm. Compromising master
compromises everything, which is why it exists separately — and why the quickstart
that puts your app there is wrong.

### The client it creates is deliberately correct

Public client, authorisation code + PKCE, and an **exact** redirect URI. The
wildcard version is finding number one in `review`, so shipping it as the default
would be a strange lesson.

### The users it creates are deliberately wrong

`emailVerified=false`, on purpose. `review` flags it, because if anything in your
application trusts the `email` claim, unverified email is a full account-takeover
path and it is not obvious until someone shows you.

---

## `jwt-decode.py`

```bash
./jwt-decode.py "$TOKEN"
./jwt-decode.py "$TOKEN" --expect-iss http://localhost:8080/realms/blueteam --expect-aud my-app
./jwt-decode.py "$TOKEN" --jwks http://localhost:8080/realms/blueteam/protocol/openid-connect/certs
echo "$TOKEN" | ./jwt-decode.py -
```

### Why not just use a website

Because the website gets your token. In a lab that is an inconvenience; with a
production token it is an incident, and the habit is what carries over.

### It refuses to say "valid"

Without `--jwks` it prints **NOT VERIFIED**, in yellow, with an explanation.
Decoding is not verifying, and an application that stops at decoding is the most
common JWT vulnerability there is. A tool that implies otherwise is worse than no
tool.

It also flags `alg: none` and symmetric `HS*` algorithms, prints how long the
token remains valid, and points out the `email_verified: false` + `email`
combination when it sees it.

---

## `oidc-flow.py`

```bash
./oidc-flow.py --discover --issuer http://localhost:8080/realms/blueteam
./oidc-flow.py --issuer http://localhost:8080/realms/blueteam --client my-app
```

Performs a real authorisation code + PKCE flow against your own Keycloak, opens a
browser, catches the redirect on `localhost:3000`, exchanges the code and decodes
the result — narrating every step. Standard library only.

### It explains PKCE by doing it

The verifier is generated and **held**; only the SHA-256 challenge goes out over
the front channel. Then the exchange sends the verifier over the back channel and
the script says what that buys you:

> An attacker who intercepts the authorisation code cannot redeem it, because
> redemption requires the verifier, and the verifier never travelled over the
> front channel.

And what it does **not** buy you:

> PKCE does not stop a wildcard redirect URI sending the code to an
> attacker-controlled path in the first place. Different problem, different
> control — and it is finding number one in `keycloak-lab.sh review`.

### It checks `state` and stops if it does not match

With an explanation rather than an error code. `state` binds the response to the
request you made; a mismatch means the response belongs to someone else's request.

### Step 6 is the one that matters

The ID token and the access token are printed side by side with what each is
**for**. Confusing them is the most common OIDC integration bug and it produces
real vulnerabilities — applications accepting an ID token as an API credential,
or reading an access token as an identity assertion.

> ID token → your app, once, at login.
> Access token → the API, with every request.
