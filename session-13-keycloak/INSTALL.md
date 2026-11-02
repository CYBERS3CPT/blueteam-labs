# Installing Keycloak — step by step

`keycloak-lab.sh up` gets you a Keycloak in thirty seconds. That is the point of
it, and also the problem: everything it skips (TLS, a real database, a reverse
proxy, an admin that is not called `admin`) is exactly what an attacker finds
first on a real one.

This manual covers the part the script skips. Three paths, in increasing order
of honesty:

| Path | What you get | Use it for |
|---|---|---|
| **A. Dev mode** | One container, HTTP, embedded database, nothing survives | The session labs. Nothing else |
| **B. Bare metal / VM** | Ubuntu, OpenJDK, PostgreSQL, nginx + Let's Encrypt, systemd | Understanding every moving part. Recommended |
| **C. Containers** | Optimised image + PostgreSQL in Docker Compose, behind a proxy | When you already run containers and know why |

Do path A first, then path B. Path C is path B with the parts hidden inside
images, which is fine once you know what the parts are.

> **Version.** Written against **Keycloak 26.8.1**. Keycloak has no LTS line:
> security fixes land only in the newest release. Check
> <https://github.com/keycloak/keycloak/releases> before you start, pin the
> version you install, and read the upgrading guide for every version you jump
> over. "latest" is not a version, it is a surprise you scheduled for later.

---

## 0. Concepts you need before you type anything

**Dev mode vs production mode.** `kc.sh start-dev` enables HTTP, relaxes hostname
checks and uses an embedded file database. `kc.sh start` does the opposite:
it refuses to run without HTTPS (or an explicit statement that a proxy is
terminating it) and without a hostname. If `start` complains, it is usually
right.

**Build options vs runtime options.** Some options (`db`, `health-enabled`,
`metrics-enabled`, features) are *baked in* by `kc.sh build`. Others (hostname,
passwords, ports) are read at every start. Change a build option and you must
rebuild. `start --optimized` skips the build check and starts faster. It also
assumes you actually rebuilt, so it will not remind you.

**Configuration sources**, highest priority first:

1. command-line options (`--db-password=...`): **never for secrets**, because
   they end up in `ps` output and shell history
2. environment variables: `KC_` + option name in capitals with dashes turned
   into underscores (`db-url-host` → `KC_DB_URL_HOST`)
3. `conf/keycloak.conf`: one `option=value` per line
4. a Java keystore (for secrets, if you want them out of plain files)

**The master realm** is for administering Keycloak. Your applications live in
their own realm. Compromising master compromises every realm, which is why the
proxy configuration below makes it unreachable from the internet.

**No default admin.** Keycloak creates the first administrator only from a local
connection, or from bootstrap variables/commands. That admin is meant to be
**temporary**: you replace it with a named admin who uses MFA, then delete it.

---

## Path A — dev mode (the lab)

Prerequisites: Docker or Podman, 2 GB of free RAM.

```bash
docker run --name kc-dev -p 127.0.0.1:8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.8.1 start-dev
```

- `-p 127.0.0.1:8080:8080` binds to loopback only. Without the `127.0.0.1:` part,
  your lab Keycloak with `admin/admin` is listening on every interface you
  have, including the café Wi-Fi.
- Older guides use `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD`. Those names were
  deprecated in Keycloak 26. Use the `KC_BOOTSTRAP_ADMIN_*` ones.

Open <http://localhost:8080/admin>, log in, and then continue with the session
script, which builds the realm, client and users for you:

```bash
./keycloak-lab.sh realm
./keycloak-lab.sh review
```

Nothing here survives `docker rm`. That is a feature.

---

## Path B — bare metal / VM (Ubuntu 24.04 LTS)

What you will end up with:

```
 internet ──443──▶ nginx (TLS, path filtering) ──127.0.0.1:8080──▶ Keycloak (systemd)
                                                                    │
                                     127.0.0.1:9000 (health/metrics)│
                                                                    ▼
                                                     PostgreSQL (127.0.0.1:5432)
```

Assumptions, replace as you go:

| Placeholder | Meaning |
|---|---|
| `sso.example.org` | the public DNS name, already pointing at the VM |
| `203.0.113.0/24` | the network your administrators connect from |
| `26.8.1` | the Keycloak version you pinned |

Minimum for a lab or small organisation: 2 vCPU, 4 GB RAM, 20 GB disk. For real
numbers use the *Concepts for sizing CPU and memory resources* guide on
keycloak.org. It is based on measurements, not on guesses like this one.

### B1. Prepare the system

```bash
sudo apt update && sudo apt full-upgrade -y
sudo timedatectl set-timezone UTC        # tokens are timestamps. Logs too.
timedatectl status                       # "System clock synchronized: yes"
```

Clock synchronisation is not optional: tokens carry `iat`/`exp`, and a few
minutes of skew between Keycloak and an application produces login failures
that look random.

Create a dedicated system user. Keycloak never runs as root:

```bash
sudo useradd --system --home-dir /opt/keycloak --shell /usr/sbin/nologin keycloak
```

Firewall: SSH and the web, nothing else.

```bash
sudo apt install -y ufw
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

Ports 8080 (Keycloak HTTP) and 9000 (management) stay closed to the outside.
Section B6 binds 8080 to loopback anyway. The firewall is there for the day
somebody changes that.

### B2. Install Java

Keycloak supports OpenJDK 17, 21 and 25 (all LTS). The project recommends the
newest one, currently **25**. It is available on Ubuntu 24.04 from the
`universe` component (`noble-updates`):

```bash
sudo apt install -y openjdk-25-jre-headless
java -version          # expect: openjdk version "25..."
```

If `java -version` shows something older, more than one JDK is installed. Fix
the default with `sudo update-alternatives --config java`.

### B3. Install PostgreSQL and create the database

The default `dev-file` database is not for production. Keycloak's own
documentation says so, and it is the first thing that breaks under two
simultaneous logins. Ubuntu 24.04 ships PostgreSQL 16, which is in the
supported range (14–18).

```bash
sudo apt install -y postgresql
sudo systemctl enable --now postgresql
```

Generate a password and keep it for B6 (a password manager, not a sticky note):

```bash
openssl rand -base64 32 | tr -d '/+=' ; echo
```

Create the role and the database. `--pwprompt` asks for the password
interactively, so it never appears in your shell history:

```bash
sudo -u postgres createuser --pwprompt keycloak
sudo -u postgres createdb --owner=keycloak --encoding=UTF8 \
     --template=template0 keycloak
```

Check:

```bash
sudo -u postgres psql -c '\l keycloak'      # owner keycloak, encoding UTF8
sudo ss -ltnp | grep 5432                   # 127.0.0.1:5432 only, NOT 0.0.0.0
```

> **MariaDB/MySQL instead?** Supported (MariaDB 10.6/10.11/11.4/11.8, MySQL
> 8.0/8.4). Create the database with `CHARACTER SET utf8mb4 COLLATE
> utf8mb4_unicode_ci`. Keycloak uses the database default charset for new tables,
> so set it *before* the first start. On MySQL, also set
> `sql_generate_invisible_primary_key=OFF` beforehand or the schema creation
> fails with `Multiple primary key defined (1068)`.

### B4. Download and verify Keycloak

```bash
KC_VERSION=26.8.1
cd /tmp
curl -fLO "https://github.com/keycloak/keycloak/releases/download/${KC_VERSION}/keycloak-${KC_VERSION}.tar.gz"
curl -fLO "https://github.com/keycloak/keycloak/releases/download/${KC_VERSION}/keycloak-${KC_VERSION}.tar.gz.sha1"
curl -fLO "https://github.com/keycloak/keycloak/releases/download/${KC_VERSION}/keycloak-${KC_VERSION}.tar.gz.asc"
```

**Integrity:** the `.sha1` file contains only the hash, with no filename and no
newline, so `sha1sum -c` needs help:

```bash
echo "$(cat keycloak-${KC_VERSION}.tar.gz.sha1)  keycloak-${KC_VERSION}.tar.gz" | sha1sum -c -
# keycloak-26.8.1.tar.gz: OK
```

That proves the download is not corrupted. It does **not** prove who made it:
anyone who can replace the tarball can replace the `.sha1` next to it.

**Authenticity** comes from the signature:

```bash
gpg --verify keycloak-${KC_VERSION}.tar.gz.asc keycloak-${KC_VERSION}.tar.gz
```

The first time, gpg will say it does not have the public key, and print the
key's fingerprint. Get the key from the **Signing keys** link on
<https://www.keycloak.org/downloads>, import it, compare the fingerprint, and
verify again. For the record, the 26.8.1 signature reports
`861A B50E 8CC6 611F B6BC  01A6 B8F1 2EA2 6FD6 EEBA`. Do not trust that because
this manual says so. Trust it because keycloak.org says the same thing. A
fingerprint copied from the same place as the file proves nothing, and that
also applies to this document.

Record the hash you installed. It is the first line of your change record:

```bash
sha256sum keycloak-${KC_VERSION}.tar.gz
```

### B5. Install

One directory per version, plus a symlink. Upgrades and rollbacks then become
swapping a link instead of untangling an overwritten tree.

```bash
sudo tar -xzf keycloak-${KC_VERSION}.tar.gz -C /opt
sudo ln -sfn /opt/keycloak-${KC_VERSION} /opt/keycloak
sudo chown -R keycloak:keycloak /opt/keycloak-${KC_VERSION}
ls -l /opt/keycloak        # → /opt/keycloak-26.8.1
```

### B6. Configure

Replace the shipped `conf/keycloak.conf` (keep the original for reference):

```bash
sudo mv /opt/keycloak/conf/keycloak.conf /opt/keycloak/conf/keycloak.conf.orig
sudo -u keycloak tee /opt/keycloak/conf/keycloak.conf >/dev/null <<'EOF'
# --- database (build-time: db) ---
db=postgres
db-url-host=127.0.0.1
db-url-database=keycloak
db-username=keycloak
db-password=CHANGE_ME_TO_THE_PASSWORD_FROM_B3

# --- observability (build-time) ---
health-enabled=true
metrics-enabled=true

# --- HTTP: TLS is terminated by nginx on the same host ---
http-enabled=true
http-host=127.0.0.1
http-port=8080

# --- reverse proxy ---
proxy-headers=xforwarded
proxy-trusted-addresses=127.0.0.1

# --- hostname (v2): the public URL, scheme included ---
hostname=https://sso.example.org

# --- load shedding: answer 503 instead of queuing forever ---
http-max-queued-requests=1000

# --- logging ---
log=console
EOF
sudo chmod 600 /opt/keycloak/conf/keycloak.conf
sudo -u keycloak nano /opt/keycloak/conf/keycloak.conf     # put the real password in
```

What each block is for:

- **`http-enabled=true` is not a downgrade here.** nginx terminates TLS. Without
  this line, `start` refuses to run because it sees no certificate. The
  combination of `http-host=127.0.0.1` and the firewall means plain HTTP never
  leaves the machine. If nginx is on another host, that hop must be TLS too:
  use `https-certificate-file` / `https-certificate-key-file` (port 8443) and
  drop `http-enabled`.
- **`proxy-headers=xforwarded`** tells Keycloak to believe `X-Forwarded-*`.
  **`proxy-trusted-addresses`** restricts *whom* it believes. Without it, a
  client that reaches Keycloak directly could forge its own source address in
  the logs and in brute-force detection.
- **`hostname` with the full URL** fixes the issuer (`iss`) in every token. If
  it is wrong, tokens are issued for a URL nobody uses, and every application
  rejects them, correctly.
- **`http-max-queued-requests`**: there is no limit by default. Under load,
  queued requests pile up until memory runs out. With a limit, the excess gets
  an immediate 503, which degrades gracefully instead of falling over.
- **Separate admin hostname (optional, better):** add
  `hostname-admin=https://sso-admin.example.org` and serve that name only on the
  internal network. Section B11 does the cheaper version: path filtering on one
  name.

### B7. Build

```bash
sudo -u keycloak /opt/keycloak/bin/kc.sh build
sudo -u keycloak /opt/keycloak/bin/kc.sh show-config | grep -E 'kc\.(db|health|metrics|hostname|proxy|http)'
```

`build` bakes in the database driver, health and metrics. `show-config` shows
what Keycloak will actually use, and which source each value came from. A
misspelled option in `keycloak.conf` does not show up there. Keycloak warns
about it in the log, and that warning is easy to miss.

### B8. Create the temporary admin

With Keycloak **stopped** (it is: you have not started it yet):

```bash
sudo -u keycloak /opt/keycloak/bin/kc.sh bootstrap-admin user \
     --username tmpadm --optimized
```

It prompts for the password, so nothing goes into history or `ps`. This account
is temporary by design: B12 replaces it.

> Alternative: set `KC_BOOTSTRAP_ADMIN_USERNAME` / `KC_BOOTSTRAP_ADMIN_PASSWORD`
> for the first start only. They are ignored once a master admin exists, but they
> stay in the unit file or environment until someone remembers to remove them.
> The command above leaves nothing behind.

### B9. systemd unit

There is no official unit. This one runs as the `keycloak` user, restarts on
failure, and limits what the process can touch:

```bash
sudo tee /etc/systemd/system/keycloak.service >/dev/null <<'EOF'
[Unit]
Description=Keycloak identity and access management
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=exec
User=keycloak
Group=keycloak
WorkingDirectory=/opt/keycloak
Environment=JAVA_OPTS_APPEND=-Djava.net.preferIPv4Stack=true
ExecStart=/opt/keycloak/bin/kc.sh start --optimized
# the JVM exits 143 on SIGTERM; that is a clean stop, not a failure
SuccessExitStatus=143
Restart=on-failure
RestartSec=5
TimeoutStartSec=180
LimitNOFILE=65536

# hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now keycloak
journalctl -u keycloak -f          # wait for "Keycloak 26.8.1 ... started in"
```

`Requires=postgresql.service` is only appropriate when the database is on the
same host. With a remote database, remove it and keep `After=`.

`systemd-analyze security keycloak` scores the unit. Each directive it flags is
something you either justify or add.

### B10. Check that it answers, locally

```bash
sudo ss -ltnp | grep -E ':(8080|9000) '
# 127.0.0.1:8080 ... java
# *:9000 or 127.0.0.1:9000 ... java   (the firewall from B1 covers both cases)

curl -fsS --head http://127.0.0.1:9000/health/ready     # HTTP/1.1 200 OK
curl -fsS http://127.0.0.1:9000/health | head -c 300; echo
```

Health and metrics live on the **management port 9000**, not on 8080. If 9000
does not answer, `health-enabled` was not in place when you ran `build`.

### B11. nginx and Let's Encrypt

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

First, a port-80 server so certbot can prove you control the name:

```bash
sudo tee /etc/nginx/sites-available/keycloak >/dev/null <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name sso.example.org;
    location / { return 301 https://$host$request_uri; }
}
EOF
sudo ln -s /etc/nginx/sites-available/keycloak /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
sudo certbot certonly --nginx -d sso.example.org
```

Then the full configuration. Read the `location` blocks carefully: **this is the
security boundary**, and it follows Keycloak's own list of what to expose.

```bash
sudo tee /etc/nginx/sites-available/keycloak >/dev/null <<'EOF'
upstream keycloak {
    server 127.0.0.1:8080;
    keepalive 16;
}

server {
    listen 80;
    listen [::]:80;
    server_name sso.example.org;
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name sso.example.org;

    ssl_certificate     /etc/letsencrypt/live/sso.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sso.example.org/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_protocols TLSv1.2 TLSv1.3;

    server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000" always;

    # Keycloak sends large headers and cookies; nginx's defaults are too small
    # and fail with "upstream sent too big header" -> 502 after login.
    proxy_buffer_size       128k;
    proxy_buffers           4 256k;
    proxy_busy_buffers_size 256k;

    proxy_http_version 1.1;
    proxy_set_header Connection        "";
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-Port  $server_port;

    # --- public: what applications and users need -------------------------
    location /realms/     { proxy_pass http://keycloak; }
    location /resources/  { proxy_pass http://keycloak; }
    location /.well-known/ { proxy_pass http://keycloak; }

    # --- administrators only ----------------------------------------------
    # The longest matching prefix wins, so these override /realms/ above.
    location /realms/master/ {
        allow 203.0.113.0/24;
        deny  all;
        proxy_pass http://keycloak;
    }
    location /admin/ {
        allow 203.0.113.0/24;
        deny  all;
        proxy_pass http://keycloak;
    }

    # --- everything else, including /metrics and /health: nothing ----------
    location / { return 404; }
}
EOF
sudo nginx -t && sudo systemctl reload nginx
```

Why each decision:

- **`/realms/master/` is admin-only.** The admin console logs in through the
  master realm. No application should, so blocking it from the internet costs
  nothing and removes the most valuable realm from the attack surface.
- **`/admin/` is admin-only.** The console and the Admin REST API. Exposed admin
  paths are, in Keycloak's own words, an unnecessary attack vector.
- **`/metrics` and `/health` are not proxied at all.** They live on port 9000,
  which you monitor from the inside.
- **`location / { return 404; }`** is default deny. A new Keycloak path appears
  in some future version? It stays closed until you decide otherwise.
- `listen 443 ssl http2` is the syntax for nginx 1.24 (Ubuntu 24.04). From
  1.25.1 onwards it is `listen 443 ssl;` plus `http2 on;`.

Renewal is handled by `certbot.timer`. Test it now rather than in 89 days:

```bash
sudo certbot renew --dry-run
systemctl list-timers certbot.timer
```

### B12. First login, and getting rid of `tmpadm`

From an address inside `203.0.113.0/24`, open
<https://sso.example.org/admin/> and log in as `tmpadm`. Then, in the **master**
realm:

1. **Users → Create new user**: a named account (`jsilva`, not `admin2`).
   Set a password under *Credentials*, with *Temporary* off.
2. **Role mapping → Assign role → Filter by realm roles → `admin`**.
3. **Required user actions → Configure OTP**, so the account cannot log in
   without enrolling MFA.
4. Log out. Log in as the new account, enrol OTP, and check that you can see the
   realms.
5. As the new account: **Users → `tmpadm` → Delete**.

Then harden master itself (**Realm settings**):

- **Security defenses → Brute force detection**: on.
- **Events → User events settings** and **Admin events settings**: on, with a
  retention period. An attacker who adds a redirect URI to a client has built a
  durable back door, and that generates exactly one log line, if you keep it.
- **Sessions**: shorten *SSO Session Idle* for master. Administrators can log in
  again.

Now create the realm for your applications. Never master. Run
`./keycloak-lab.sh review` against it (with `KC_REALM` / `KC_ADMIN` set) and fix
what it finds.

### B13. Prove it works

Writing "installed OK" in a report proves nothing. These commands produce
evidence:

```bash
# 1. discovery document, with the issuer you configured
curl -fsS https://sso.example.org/realms/<your-realm>/.well-known/openid-configuration | jq -r .issuer
# → https://sso.example.org/realms/<your-realm>

# 2. what Keycloak believes about its own hostname (turn it off again afterwards)
#    add hostname-debug=true to keycloak.conf, restart, open
#    https://sso.example.org/realms/<your-realm>/hostname-debug

# 3. the boundary holds (run from OUTSIDE the admin network)
curl -s -o /dev/null -w '%{http_code}\n' https://sso.example.org/admin/                 # 403
curl -s -o /dev/null -w '%{http_code}\n' https://sso.example.org/realms/master/account  # 403
curl -s -o /dev/null -w '%{http_code}\n' https://sso.example.org/metrics                # 404
curl -s -o /dev/null -w '%{http_code}\n' https://sso.example.org/health                 # 404

# 4. TLS: protocols and certificate
nmap --script ssl-enum-ciphers -p 443 sso.example.org     # TLSv1.2 and TLSv1.3 only

# 5. a real flow
../session-13-keycloak/oidc-flow.py --discover --issuer https://sso.example.org/realms/<your-realm>
```

### B14. Backups

Two things to back up, and one thing that looks like a backup but is not:

```bash
# the database: users, credentials, sessions, configuration — everything
sudo -u postgres pg_dump -Fc keycloak > keycloak-$(date -u +%Y%m%dT%H%M%SZ).dump

# the configuration that is NOT in the database
sudo tar -czf keycloak-conf-$(date -u +%Y%m%dT%H%M%SZ).tgz \
     /opt/keycloak/conf /etc/systemd/system/keycloak.service /etc/nginx/sites-available/keycloak
```

A **realm export** (`keycloak-lab.sh export`, or *Realm settings → Action →
Partial export*) is configuration, not a backup: password hashes are not in
it, so you cannot restore a working user base from it. It is also not harmless,
since client secrets and mappings live in there. Store it accordingly.

Dumps contain credential hashes. Use `chmod 600`, keep them off the same disk,
and test a restore before you need one.

### B15. Upgrades

1. Read the **Upgrading Guide** for every version between yours and the target.
   Skipping a version does not let you skip reading its notes.
2. Back up the database (B14). Keycloak migrates the schema automatically on the
   first start of a new version, and **there is no downgrade**: the dump is
   your rollback.
3. Download and verify the new version (B4), extract it next to the old one.
4. Copy `conf/keycloak.conf`, plus `providers/` and `themes/` if you use them.
5. `sudo -u keycloak /opt/keycloak-<new>/bin/kc.sh build`
6. `sudo systemctl stop keycloak`, `ln -sfn /opt/keycloak-<new> /opt/keycloak`,
   `sudo systemctl start keycloak`, then watch the journal for the migration.
7. Run B13 again. Keep the old directory for a few days, then remove it.

---

## Path C — containers (Docker Compose)

Same architecture as path B, packaged differently. Keep nginx (or another TLS
proxy) in front exactly as in B11. The container only replaces B2–B9.

### C1. An optimised image

The official image is generic. Building your own bakes in the database driver
and health checks, so the container starts with `--optimized` and skips the
build step at every start.

`Containerfile`:

```dockerfile
FROM quay.io/keycloak/keycloak:26.8.1 AS builder
ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
WORKDIR /opt/keycloak
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.8.1
COPY --from=builder /opt/keycloak/ /opt/keycloak/
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
```

```bash
docker build -t keycloak-local:26.8.1 -f Containerfile .
```

### C2. Compose

`.env` (`chmod 600`, and listed in `.gitignore` **before** the first commit):

```bash
POSTGRES_PASSWORD=<openssl rand -base64 32 | tr -d '/+='>
KC_BOOTSTRAP_ADMIN_PASSWORD=<another one, used once>
```

`compose.yaml`:

```yaml
services:
  postgres:
    image: postgres:18
    restart: unless-stopped
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      # postgres 18 images keep data under /var/lib/postgresql/<major>/,
      # so mount the parent, not /var/lib/postgresql/data as older guides say
      - pgdata:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak -d keycloak"]
      interval: 10s
      retries: 5

  keycloak:
    image: keycloak-local:26.8.1
    restart: unless-stopped
    command: ["start", "--optimized"]
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      KC_DB_URL_HOST: postgres
      KC_DB_URL_DATABASE: keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: ${POSTGRES_PASSWORD}
      KC_HOSTNAME: https://sso.example.org
      KC_HTTP_ENABLED: "true"
      KC_PROXY_HEADERS: xforwarded
      KC_HTTP_MAX_QUEUED_REQUESTS: "1000"
      # first start only: remove both lines once the named admin exists (B12)
      KC_BOOTSTRAP_ADMIN_USERNAME: tmpadm
      KC_BOOTSTRAP_ADMIN_PASSWORD: ${KC_BOOTSTRAP_ADMIN_PASSWORD}
    ports:
      - "127.0.0.1:8080:8080"     # loopback: nginx on the host is the only client
    healthcheck:
      # the image ships without curl, on purpose; bash can still open a socket
      test: ["CMD-SHELL", "exec 3<>/dev/tcp/127.0.0.1/9000 && printf 'GET /health/ready HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' >&3 && grep -q '\"UP\"' <&3"]
      interval: 15s
      timeout: 5s
      retries: 10
      start_period: 60s

volumes:
  pgdata:
```

```bash
docker compose up -d
docker compose ps                       # keycloak: healthy
docker compose logs -f keycloak
```

Notes specific to containers:

- **Port 9000 is not published.** Health is checked inside the container. If
  external monitoring needs it, publish it on `127.0.0.1` only.
- **`proxy-trusted-addresses`** is not set above because the host's nginx reaches
  the container through the Docker bridge, whose gateway address depends on your
  setup. Find it (`docker network inspect`) and set `KC_PROXY_TRUSTED_ADDRESSES`
  before you go anywhere near production.
- **Postgres has no published port.** Only the `keycloak` service can reach it,
  over the Compose network.
- Pin both images by version (better: by digest). `postgres:latest` will one day
  be a new major version, and a major PostgreSQL upgrade is not something you
  want happening on a Tuesday restart.

The rest (B11 proxy, B12 first login, B13 evidence, B14 backups with
`docker compose exec postgres pg_dump`, B15 upgrades by rebuilding the image)
applies unchanged.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `start` exits: *HTTPS must be configured* / *hostname must be set* | production mode doing its job | B6: `hostname`, and either TLS options or `http-enabled=true` behind a proxy |
| Browser shows **"HTTPS required"** | realm `sslRequired=external`, and Keycloak thinks the request came over HTTP from outside | proxy not sending `X-Forwarded-Proto`, or `proxy-headers` missing. Do **not** set `sslRequired=none` |
| Login loops, or redirects to `localhost:8080` | hostname wrong or not trusted from headers | `hostname` = full public URL; check `/realms/<realm>/hostname-debug` |
| `502` right after login, nginx log says **upstream sent too big header** | nginx proxy buffers too small for Keycloak cookies | the `proxy_buffer*` lines in B11 |
| **Invalid parameter: redirect_uri** | the client's redirect URI does not match **exactly** | fix the client. Do not "fix" it with `/*`, that is finding #1 in `keycloak-lab.sh review` |
| *Local access required* when creating the first admin | the first admin can only be created from localhost | B8 (`bootstrap-admin`) or bootstrap env vars |
| `UnsupportedClassVersionError` | Java too old for this Keycloak | B2; check `java -version` as the `keycloak` user |
| *build time options differ* / options silently ignored | changed a build option without `kc.sh build` | rebuild (B7), or drop `--optimized` once to see the error |
| Port 9000 refuses connections | health/metrics not built in | `health-enabled=true` then `kc.sh build` |
| Accents garbled in user names | database not UTF-8 / utf8mb4 | recreate the database (B3) before first start. It is painful afterwards |
| Tokens rejected by apps "at random" | clock skew | `timedatectl` on every machine involved |

Logs: `journalctl -u keycloak` (path B) or `docker compose logs keycloak`
(path C). For one investigation, `log-level=info,org.keycloak.events:debug`
shows every event as it happens. Remove it afterwards, because it is verbose
and it logs user identifiers.

---

## Deliverable checklist

The session deliverable asks for a realm export and a design rationale. For the
installation itself, a reviewer should be able to check each of these with a
command, not with your word for it:

- [ ] Version pinned, tarball/image hash recorded, signature verified
- [ ] Runs as an unprivileged user (path B) or from a pinned image (path C)
- [ ] PostgreSQL (or MariaDB/MySQL), UTF-8, not `dev-file`
- [ ] TLS at the edge, HTTP only on loopback, `TLSv1.2`/`TLSv1.3` only
- [ ] `/admin/` and `/realms/master/` unreachable from outside the admin network
- [ ] `/metrics` and `/health` not proxied
- [ ] Temporary admin deleted; named admin with OTP
- [ ] Brute force detection and admin events on, in master **and** your realm
- [ ] Applications in their own realm; `keycloak-lab.sh review` clean or justified
- [ ] Backup taken **and restored once** somewhere else

---

## Sources

Official documentation (keycloak.org), read before writing this manual:

- Getting started (Docker, OpenJDK): <https://www.keycloak.org/getting-started/getting-started-docker>, <https://www.keycloak.org/getting-started/getting-started-zip>
- Configuring Keycloak (sources, build vs optimized): <https://www.keycloak.org/server/configuration>
- Configuring for production (checklist): <https://www.keycloak.org/server/configuration-production>
- Supported configurations (JDK 17/21/25): <https://www.keycloak.org/server/supported-configurations>
- Database: <https://www.keycloak.org/server/db>
- Hostname v2: <https://www.keycloak.org/server/hostname>
- Reverse proxy (paths to expose): <https://www.keycloak.org/server/reverseproxy>
- TLS: <https://www.keycloak.org/server/enabletls>
- Running in a container: <https://www.keycloak.org/server/containers>
- Health checks: <https://www.keycloak.org/observability/health>
- Admin bootstrap and recovery: <https://www.keycloak.org/server/bootstrap-admin-recovery>
- Releases and upgrading: <https://github.com/keycloak/keycloak/releases>, <https://www.keycloak.org/docs/latest/upgrading/>
- Ubuntu package `openjdk-25-jdk-headless` (noble): <https://packages.ubuntu.com/en/noble/java/openjdk-25-jdk-headless>
