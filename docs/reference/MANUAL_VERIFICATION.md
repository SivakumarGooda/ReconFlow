# Manual Verification — test checklist per service

> **Reference — not a step.** How to check things by hand, for looking up. The steps are in [the whole picture](../README.md).

> [!WARNING]
> **Authorized engagements only.**

How to check each service by hand: confirm a finding, rule out a false
positive, or test a port automation didn't cover. Each section lists the CLI
commands; [MANUAL_METASPLOIT.md](../workflow/MANUAL_METASPLOIT.md) has the matching
Metasploit module where one exists.

This is a static reference; ReconFlow does not regenerate it. Steps marked
**manual only** or **opt-in** act on the target — they're collected in
[MANDATORY_CHECKS.md](../workflow/MANDATORY_CHECKS.md), where you decide which are in
scope.

> [!TIP]
> Commands here are generic (`TARGET`, `PORT`), for one host. To run one on
> **every** host, wrap it in `each` from `tools/rf-helpers.sh` — `TARGET` →
> `$T`, `PORT` → `$P` (see [MANDATORY_CHECKS.md → Before you start](../workflow/MANDATORY_CHECKS.md#before-you-start--run-on-every-target));
> its output reaches the report automatically. The reproduce commands in
> `FINDINGS.md` and `manual-checklist.md` are already filled in for your
> hosts. How to
> record: [MANDATORY_CHECKS.md → How to record results](../workflow/MANDATORY_CHECKS.md#how-to-record-results).

> [!CAUTION]
> Steps marked **⚠️ Caution** act on the target — they log in, guess, write,
> run code, pull secrets or make it send traffic. Run them only if they're in
> scope (check account-lockout policy before any login attempt). Every one is
> also in [MANDATORY_CHECKS.md → Part 2](../workflow/MANDATORY_CHECKS.md#3-risky-checks).
> Unmarked steps only read what the service already shows.

`TARGET` and `PORT` are placeholders: always use the port the service was
actually found on (see `FINDINGS.md` / `open-ports/`).

## Contents

- [By port](#by-port)
- [Web ports](#web-ports)
- [SSL/TLS](#ssltls)
- [General triage rules](#general-triage-rules)
- [See also](#see-also)

---

## By port

### 21/tcp — FTP

- Version: `nmap -Pn -sV -pPORT TARGET` → `vsftpd 2.3.4` or `ProFTPD 1.3.3c`
  are backdoored releases (Critical).
- Anonymous login: `nmap -Pn -pPORT --script ftp-anon TARGET` →
  `Anonymous FTP login allowed (FTP code 230)`.
- ⚠️ **Caution — logs in:** Connect: `ftp -P PORT TARGET` → try `anonymous` / `anonymous` (any email as
  password).
- ⚠️ **Caution — writes a file:** If logged in: `ls -la`, `pwd`; `put` a harmless test file to check write
  access, then delete it.

### 22/tcp — SSH

- Banner: `nc TARGET PORT` → record the version.
- Allowed auth: `ssh -v -p PORT user@TARGET` (publickey vs password).
- Weak algorithms / keys: `ssh-audit -p PORT TARGET`.

### 23/tcp — Telnet

- `nc -nv TARGET PORT` or `telnet TARGET PORT` → observe the login prompt /
  banner. A cleartext remote login is a finding on its own.
- ⚠️ **Caution — login attempts:** Try vendor default credentials for the fingerprinted device (if in scope).

### 25/tcp — SMTP

- ⚠️ **Caution — guessing (wordlist part):** User enumeration: `nc -nv TARGET PORT` → `EHLO x`, then `VRFY root`,
  `EXPN`. `250` / `252` = user exists, `550` = no such user. Wordlist
  guessing (`smtp-enum-users`, `smtp_enum`) is **manual only** — see
  [MANDATORY_CHECKS.md](../workflow/MANDATORY_CHECKS.md#3-risky-checks).
- ⚠️ **Caution — sends traffic for you:** Open relay (**manual only** — see [MANDATORY_CHECKS.md](../workflow/MANDATORY_CHECKS.md#3-risky-checks)):
  `nmap -Pn -pPORT --script smtp-open-relay TARGET`. To confirm
  by hand, `nc TARGET PORT` → `EHLO x`, `MAIL FROM:<a@external1.example>`,
  `RCPT TO:<b@external2.example>` — a `250` for the recipient means it would
  relay. Send `RSET`, `QUIT`; don't send real mail.

### 53 — DNS

- Zone transfer (needs the domain): `dig axfr @TARGET -p PORT domain.tld` —
  success = full record dump.
- Open recursion: `dig @TARGET -p PORT example.com A +recurse` → an answer
  with the `ra` flag.

### 69/udp — TFTP

- `tftp TARGET` → `get` a likely config file name. TFTP has no
  authentication.

### 79/tcp — Finger

- `finger @TARGET`, `finger root@TARGET` → user enumeration.

### 88/tcp — Kerberos

- ⚠️ **Caution — guessing:** Usually means a domain controller. User enumeration needs a user list
  (opt-in): `kerbrute userenum -d <domain> --dc TARGET users.txt`.

### 110, 143/tcp — POP3 / IMAP

- ⚠️ **Caution — login attempts:** `nc TARGET PORT` → banner; try `USER` / `PASS` (POP3) or `LOGIN` (IMAP).
  Cleartext auth without STARTTLS = finding.

### 111, 2049/tcp — RPC / NFS

- `showmount -e TARGET` → list exports; `*` means any host may mount.
- Export list and access rights in one go:
  `nmap -Pn -p111,2049 --script nfs-showmount,nfs-ls TARGET` → `access:`
  line per export.
- Mount read-only to confirm: `mount -t nfs TARGET:/export /mnt/x -o ro`.
- **Root export** (`/` in the list): record the mounted listing as evidence;
  this exposes the whole filesystem.
- ⚠️ **Caution — writes a file:** **Writable export** (`nfs-ls` shows `Modify Extend Delete`): mount
  read-write, create a harmless test file, delete it. Check for
  `no_root_squash` (files created as root stay owned by root).

### 123/udp — NTP

- `ntpq -c rv TARGET` → version / system disclosure.
- ⚠️ **Caution — amplification:** Amplification check (opt-in): `ntpdc -n -c monlist TARGET`.

### 135, 139, 445/tcp — SMB / MSRPC

- Version: `nmap -Pn -pPORT --script smb-os-discovery TARGET` →
  `Samba 3.0.20` – `3.0.25` = usermap_script RCE (CVE-2007-2447, Critical).
- Null-session share list: `smbclient -N -L //TARGET/ -p PORT`.
- Anonymous access level per share:
  `nmap -Pn -pPORT --script smb-enum-shares TARGET` →
  `Anonymous access: READ` or `READ/WRITE`.
- Browse a share: `smbclient -N //TARGET/ShareName -p PORT` → `ls`, `get` a
  sample file as evidence.
- Signing: `nxc smb TARGET --port PORT` → `signing:False`, or
  `nmap -Pn -pPORT --script smb2-security-mode,smb-security-mode TARGET` →
  `enabled but not required`. Either means NTLM relay is possible.
- OS / domain details: `enum4linux-ng -A TARGET`.
- MS17-010: confirm with `nmap -Pn -pPORT --script smb-vuln-ms17-010 TARGET`.

### 137/udp — NetBIOS

- `nmblookup -A TARGET` → hostname, workgroup / domain, logged-on users.

### 161/udp — SNMP

- `snmpwalk -v2c -c public TARGET` → data returned = default community
  string.
- Pull the system description `.1.3.6.1.2.1.1.1.0`, running processes and
  interfaces.
- ⚠️ **Caution — guessing:** Community-string guessing (opt-in):
  `onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt TARGET`.

### 389, 636/tcp — LDAP

- `ldapsearch -x -H ldap://TARGET:PORT -s base -b "" +` → rootDSE and naming
  contexts.
- Anonymous bind that returns directory data = finding:
  `ldapsearch -x -H ldap://TARGET:PORT -b '<namingContext>'`.

### 500/udp — IKE (VPN)

- ⚠️ **Caution — pulls a crackable hash:** `ike-scan -M TARGET`; aggressive mode (opt-in) `ike-scan -A -M TARGET`
  leaks a crackable PSK hash.

### 623/udp — IPMI

- `sudo nmap -Pn -sU -pPORT --script ipmi-version,ipmi-cipher-zero TARGET` →
  `VULNERABLE` = cipher suite 0 accepts any password.
- ⚠️ **Caution — pulls password hashes:** Hash retrieval (opt-in): `auxiliary/scanner/ipmi/ipmi_dumphashes`.

### 512, 513, 514/tcp — r-services

- Confirm the services: `nmap -Pn -sV -p512,513,514 TARGET` → `exec`,
  `login`, `shell`.
- ⚠️ **Caution — login attempts:** `rlogin -l root TARGET`, `rsh -l root TARGET id` → host-trust (`.rhosts`)
  access.

### 1099/tcp — Java RMI

- Bound names: `nmap -Pn -pPORT --script rmi-dumpregistry TARGET`.
- ⚠️ **Caution — loads remote code:** Remote class loading (**manual only** — see [MANDATORY_CHECKS.md](../workflow/MANDATORY_CHECKS.md#3-risky-checks)):
  `nmap -Pn -pPORT --script rmi-vuln-classloader TARGET`.
- Deeper enumeration: `remote-method-guesser` (rmg).

### 1433, 3306, 5432/tcp — Databases

- ⚠️ **Caution — login attempts:** MySQL blank passwords (**manual only** — see [MANDATORY_CHECKS.md](../workflow/MANDATORY_CHECKS.md#3-risky-checks)):
  `nmap -Pn -pPORT --script mysql-empty-password TARGET` →
  `root account has empty password`.
- ⚠️ **Caution — login attempts:** Try blank / default credentials with the native client:
  - MySQL: `mysql -h TARGET -P PORT -u root --skip-password -e 'select user();'`
  - Postgres: `psql -h TARGET -p PORT -U postgres`
  - MSSQL: `impacket-mssqlclient sa@TARGET -port PORT`
- Confirm whether remote connections are permitted at all (exposure finding).
- With access, list databases only (`show databases;`) as evidence.

### 1524/tcp and unknown shells

- ⚠️ **Caution — runs a command:** `nc -nv TARGET PORT` → type `id`. A `uid=` line with no login = open shell.
  Capture the output and report immediately.

### 1883/tcp — MQTT

- `nmap -Pn -pPORT --script mqtt-subscribe TARGET` → topics listed = anonymous
  subscribe allowed.
- `mosquitto_sub -h TARGET -p PORT -t '#' -v` → anonymous read of every
  topic.

### 2375/tcp — Docker API

- `curl -sk http://TARGET:PORT/version` (`https://` on 2376) → JSON with
  `ApiVersion` = unauthenticated Docker API, equivalent to root on the host.
  Don't start containers.

### 2379, 6443, 10250/tcp — etcd / Kubernetes

- etcd: `curl -s http://TARGET:2379/version`, then
  `etcdctl --endpoints=http://TARGET:2379 get / --prefix --keys-only`.
- API server: `curl -sk https://TARGET:6443/api/v1/namespaces` → anything
  beyond 401 / 403 = anonymous API access.
- Kubelet: `curl -sk https://TARGET:10250/pods` → a `PodList` = anonymous
  kubelet (critical).

### 3128, 8080/tcp — HTTP proxy

- ⚠️ **Caution — sends traffic for you:** Open-proxy test (**manual only** — see [MANDATORY_CHECKS.md](../workflow/MANDATORY_CHECKS.md#3-risky-checks)):
  `nmap -Pn -pPORT --script http-open-proxy TARGET` → `Potentially OPEN proxy`.
- ⚠️ **Caution — sends traffic for you:** Confirm: `curl -s -x http://TARGET:PORT http://example.com -o /dev/null -w '%{http_code}\n'`
  → `200` through the proxy.

### 3389/tcp — RDP

- `xfreerdp /v:TARGET:PORT` → observe the NLA requirement, certificate and
  warning dialogs.
- Record the encryption level and NTLM info from the nmap scripts.

### 3632/tcp — distccd

- `nmap -Pn -sV -pPORT TARGET` → `distccd` reachable from untrusted networks
  = finding (CVE-2004-2687).
- ⚠️ **Caution — runs a command:** Command-execution proof is opt-in:
  `nmap -Pn -pPORT --script distcc-cve2004-2687 TARGET` (runs a command).

### 5900/tcp — VNC

- `nmap -Pn -pPORT --script vnc-info,realvnc-auth-bypass TARGET` → security
  types; `VULNERABLE` = RealVNC auth bypass (CVE-2006-2369).
- ⚠️ **Caution — login attempts:** `vncviewer TARGET::PORT` → test for no-auth / weak-password access.

### 5984/tcp — CouchDB

- `curl -sk http://TARGET:PORT/_all_dbs` → database list without auth.

### 5985, 5986/tcp — WinRM

- ⚠️ **Caution — logs in:** Once credentials are found: `evil-winrm -i TARGET -P PORT -u user -p pass`
  confirms a foothold.

### 6000/tcp — X11

- `nmap -Pn -pPORT --script x11-access TARGET` → `X server access is granted`.
- `xdpyinfo -display TARGET:0` → display info returned = unauthenticated X
  access.

### 6379/tcp — Redis

- `redis-cli -h TARGET -p PORT INFO server` → `redis_version:` without AUTH
  = unauthenticated access. `config get dir` for detail; don't write keys.

### 6667/tcp — IRC

- `nmap -Pn -sV -pPORT --script irc-info TARGET` → server version;
  UnrealIRCd 3.2.8.1 = backdoored build (CVE-2010-2075).

### 8009/tcp — AJP

- ⚠️ **Caution — Ghostcat check reads files:** `nmap -Pn -pPORT --script ajp-methods,ajp-headers TARGET`; with Tomcat
  behind it, check Ghostcat (CVE-2020-1938) — opt-in.

### 8080, 8180, 8443/tcp — Tomcat

- ⚠️ **Caution — default-credential testing = login attempts:** `curl -sk -o /dev/null -w '%{http_code}' <scheme>://TARGET:PORT/manager/html`
  → `401` = manager deployed. Default-credential testing is opt-in.

### 8787/tcp — Ruby DRb

- ⚠️ **Caution — code-execution test runs code:** `nmap -Pn -sV -pPORT TARGET` → `drb` / `Ruby DRb RMI` reachable from
  untrusted networks = finding (DRb without an ACL permits remote method
  calls). Any code-execution test is opt-in and needs explicit scope.

### 9200/tcp — Elasticsearch

- `curl -sk http://TARGET:PORT/` → cluster JSON with `cluster_name`.
- `curl -sk 'http://TARGET:PORT/_cat/indices?v'` → index list without auth.
  Note index names only as evidence.

### 9100/tcp — JetDirect / raw printing

- ⚠️ **Caution — PRET reads files from the printer:** `nc TARGET 9100` accepts print data without auth; PJL disclosure via PRET
  (opt-in).

### Any port — Java debug (JDWP)

- ⚠️ **Caution — going further runs code:** `nmap -Pn -pPORT --script jdwp-version TARGET` → prints the JVM version =
  unauthenticated debugger, code execution in the JVM. Confirm scope before
  going further.

---

## Web ports

Any web port (80, 443, 8080, 8443, …):

- Open **both** `http://TARGET:PORT` and `https://TARGET:PORT` in a browser;
  cross-check the screenshot in `web-report.html`.
- Identify the technology: `whatweb`, Wappalyzer.
- Look for default / admin panels, directory listing, verbose errors, exposed
  `.git` / backup files.
- ⚠️ **Caution — login attempts:** Try default credentials on any login panel for the identified product (if in
  scope).
- ⚠️ **Caution — heavy scanning:** Heavier scans (opt-in): `nikto -h URL`, `nuclei -u URL`,
  `ffuf -u URL/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt`.

---

## SSL/TLS

Any TLS port, plus STARTTLS on SMTP / FTP / IMAP / POP3 / LDAP / Postgres /
MySQL:

- Protocols + ciphers: `sslscan TARGET:PORT`
  (STARTTLS: `sslscan --starttls-smtp TARGET:25`).
- Full audit: `testssl.sh TARGET:PORT`.
- Prove an old protocol is accepted:
  `openssl s_client -connect TARGET:PORT -tls1 </dev/null`
  (likewise `-tls1_1`, `-ssl3`) — a completed handshake = finding.
- Certificate:
  `openssl s_client -connect TARGET:PORT </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates`
  → expired dates, Subject = Issuer (self-signed), wrong hostname.
- Known TLS bugs:
  `nmap -Pn -pPORT --script ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params TARGET`.

---

## General triage rules

1. **Confirm the service is really that service** — version banners lie, and
   tarpits exist.
2. **Capture evidence** (command + output + screenshot) for every confirmed
   finding.
3. **Couldn't reproduce it?** Attach your evidence anyway — the report marks
   it *Not reproduced* — or tick *false positive* in `manual-checklist.md`.

---

## See also

- [MANDATORY_CHECKS.md](../workflow/MANDATORY_CHECKS.md) — step 4: everything
  automation doesn't do.
- [MANUAL_METASPLOIT.md](../workflow/MANUAL_METASPLOIT.md) — the Metasploit
  modules per service.
