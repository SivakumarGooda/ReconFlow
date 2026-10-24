# Manual Metasploit — run the automated modules yourself

> **Step 3 of 5 — only if you answered N to Metasploit** · [the whole picture](../README.md) · next: [MANDATORY_CHECKS.md](MANDATORY_CHECKS.md)

> [!WARNING]
> **Authorized engagements only.**

This is the by-hand version of ReconFlow's automatic Metasploit run. Use it
if you answered **N** to *"Also run the Metasploit modules automatically?"*
— or want to watch each module yourself. Every module the automatic run
uses is here, per service; a few blocks add safe extras, marked
`# extra — not in the automatic run`.

Every ReconFlow run writes `targets/port-<port>-<proto>-<service>.txt` (one IP
per line) in its output folder. Load those as RHOSTS — this works even if the
msf database is down. With the database up, `services -u -p <port> -R` does
the same from the imported scan.

> [!IMPORTANT]
> Credential testing and exploit modules are **not** here — automation never
> runs them, so they're in [MANDATORY_CHECKS.md](MANDATORY_CHECKS.md). Go
> through that page after this one.

## Contents

- [0. Setup](#0-setup-once-per-engagement)
- [1. The pattern for every port](#1-the-pattern-for-every-port)
- [2. Per service](#2-per-service)
- [3. After the run](#3-after-the-run)
- [4. What Metasploit alone misses](#4-what-metasploit-alone-misses)
- [5. Then: the mandatory checks](#5-then-the-mandatory-checks)

DNS amplification (`dns_amp`) and open-proxy (`open_proxy`) tests are in
[MANDATORY_CHECKS.md](MANDATORY_CHECKS.md) too — they make the target send
traffic for you.

---

## 0. Setup (once per engagement)

**Step 1 — go to the output folder first**, so `targets/` and the scan XML
are where the commands below expect them:

```bash
cd <recon-folder>        # the -o folder, e.g. cd /home/you/ReconFlow/recon-clientA
```

**Step 2 — start msfconsole with `msf-manual.rc`.** Every run writes it into
the output folder. It spools the session to `msf-manual.log` (full path),
creates the workspace, imports the scan, removes out-of-scope hosts and sets
`THREADS` — then leaves you at the `msf>` prompt. It runs no modules.

```bash
msfconsole -r msf-manual.rc        # from step 1's folder; or give its full path
```

`msf-manual.rc` also `cd`s msfconsole into the output folder, so from here
on every path is relative to it — `file:targets/…` in the blocks below
works as written, with nothing to replace. Then check what was imported:

```text
hosts
services
```

<details>
<summary>Without msf-manual.rc — the same setup by hand</summary>

```text
msfconsole -q
# FIRST — full path!
spool /full/path/to/<recon-folder>/msf-manual.log
# the name metasploit.rc uses (first lines of msf-manual.rc)
workspace -a <recon-folder-name>_<date>_<time>
# relative: you started in the folder
db_import scan-tcp.xml
# UDP scan (skipped with --no-udp)
db_import scan-udp.xml
setg THREADS 10
```

A bare `spool msf-manual.log` saves into whatever folder you started
msfconsole from — if that isn't the output folder, report.py never sees your
session.

</details>

> [!TIP]
> **The session must be spooled to `<recon-folder>/msf-manual.log`** —
> `msf-manual.rc` does it for you.
> Everything you run is then recorded, and `python3 report.py <recon-folder>`
> folds your results into the report as *Metasploit (manual)* — a hit counts
> as **Confirmed**. Several sessions? Use `msf-manual-2.log`, … — every
> `msf-manual*.log` is read. Without the spool, your results never reach the
> report.

## 1. The pattern for every port

```text
use <module>
# relative to the output folder
set RHOSTS file:targets/port-<PORT>-<proto>-<service>.txt
#   or:  services -u -p <PORT> -R
set RPORT <PORT>
# only for https / TLS-wrapped ports
set SSL true
run
back
```

- **Use the real port** from `FINDINGS.md` / `open-ports/` — FTP found on 2121
  means `RPORT 2121` and `targets/port-2121-tcp-ftp.txt`.
- **TCP and UDP on the same port:** `services -p` can't tell them apart; use
  the `targets/` file for the protocol you want.
- **Only ports you actually found:** if there's no `targets/port-<PORT>-…`
  file, nothing on that port is open — skip that block.
- **A service on several ports?** `msf_rc` from `tools/rf-helpers.sh`
  writes the block for every port it was found on — e.g.
  `msf_rc ftp-version ftp auxiliary/scanner/ftp/ftp_version`, then
  `resource msf-blocks/ftp-version.rc` (see
  [MANDATORY_CHECKS.md → Before you start](MANDATORY_CHECKS.md#before-you-start--run-on-every-target)).

---

## 2. Per service

Each block runs the scanner modules for that service; paste it whole.
The `file:targets/…` paths are relative to the output folder, where
`msf-manual.rc` puts you — paste them as they are. Only change the port
number (in the file name and `RPORT`) for a service on a non-default port.

> [!NOTE]
> Relative paths follow msfconsole's current folder. If you `cd` elsewhere
> inside msfconsole, `cd` back to the output folder first (the spool keeps
> recording to the right place either way — its path is absolute).

### CouchDB — 5984/tcp

```text
# extra — not in the automatic run
use auxiliary/scanner/couchdb/couchdb_enum
set RHOSTS file:targets/port-5984-tcp-couchdb.txt
set RPORT 5984
run
back
```

### Docker — 2375/tcp

```text
use auxiliary/scanner/http/docker_version
set RHOSTS file:targets/port-2375-tcp-docker.txt
set RPORT 2375
run
back
```

### Elasticsearch — 9200/tcp

```text
# extra — not in the automatic run
use auxiliary/gather/elasticsearch_enum
set RHOSTS file:targets/port-9200-tcp-elasticsearch.txt
set RPORT 9200
run
back
```

> [!NOTE]
> This module also downloads the first and last 5 rows of every index
> (`DOWNLOADROWS`). That is data access — check it's in scope first.

### etcd — 2379/tcp

```text
# extra — not in the automatic run
use auxiliary/scanner/etcd/version
set RHOSTS file:targets/port-2379-tcp-etcd.txt
set RPORT 2379
run
back
```

### FTP — 21/tcp

```text
use auxiliary/scanner/ftp/ftp_version
set RHOSTS file:targets/port-21-tcp-ftp.txt
set RPORT 21
run
back
use auxiliary/scanner/ftp/ftp_anonymous
set RHOSTS file:targets/port-21-tcp-ftp.txt
set RPORT 21
run
back
```

### IMAP — 143/tcp

```text
use auxiliary/scanner/imap/imap_version
set RHOSTS file:targets/port-143-tcp-imap.txt
set RPORT 143
run
back
```

### IPMI — 623/udp

```text
use auxiliary/scanner/ipmi/ipmi_version
set RHOSTS file:targets/port-623-udp-ipmi.txt
set RPORT 623
run
back
use auxiliary/scanner/ipmi/ipmi_cipher_zero
set RHOSTS file:targets/port-623-udp-ipmi.txt
set RPORT 623
run
back
```

### Java RMI — 1099/tcp

```text
use auxiliary/scanner/misc/java_rmi_server
set RHOSTS file:targets/port-1099-tcp-rmi.txt
set RPORT 1099
run
back
```

### MQTT — 1883/tcp

```text
# extra — not in the automatic run
use auxiliary/scanner/mqtt/connect
set RHOSTS file:targets/port-1883-tcp-mqtt.txt
set RPORT 1883
run
back
```

A successful connect without credentials = anonymous broker access.

### MSRPC — 135/tcp

```text
use auxiliary/scanner/dcerpc/endpoint_mapper
set RHOSTS file:targets/port-135-tcp-msrpc.txt
set RPORT 135
run
back
```

### MSSQL — 1433/tcp

```text
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS file:targets/port-1433-tcp-mssql.txt
set RPORT 1433
run
back
```

### MySQL — 3306/tcp

```text
use auxiliary/scanner/mysql/mysql_version
set RHOSTS file:targets/port-3306-tcp-mysql.txt
set RPORT 3306
run
back
```

Blank-password login is a **risky check** — ReconFlow never runs it. It's in
[MANDATORY_CHECKS.md → Risky checks](MANDATORY_CHECKS.md#3-risky-checks),
with the Metasploit version.

### NFS / RPC — 111/tcp

```text
use auxiliary/scanner/nfs/nfsmount
set RHOSTS file:targets/port-111-tcp-rpcbind.txt
set RPORT 111
run
back
```

### Oracle — 1521/tcp

```text
use auxiliary/scanner/oracle/tnslsnr_version
set RHOSTS file:targets/port-1521-tcp-oracle.txt
set RPORT 1521
run
back
```

### POP3 — 110/tcp

```text
use auxiliary/scanner/pop3/pop3_version
set RHOSTS file:targets/port-110-tcp-pop3.txt
set RPORT 110
run
back
```

### Postgres — 5432/tcp

```text
use auxiliary/scanner/postgres/postgres_version
set RHOSTS file:targets/port-5432-tcp-postgres.txt
set RPORT 5432
run
back
```

### RDP — 3389/tcp

```text
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS file:targets/port-3389-tcp-rdp.txt
set RPORT 3389
run
back
```

### Redis — 6379/tcp

```text
use auxiliary/scanner/redis/redis_server
set RHOSTS file:targets/port-6379-tcp-redis.txt
set RPORT 6379
run
back
```

### rsync — 873/tcp

```text
use auxiliary/scanner/rsync/modules_list
set RHOSTS file:targets/port-873-tcp-rsync.txt
set RPORT 873
run
back
```

### SIP — 5060/udp

```text
use auxiliary/scanner/sip/options
set RHOSTS file:targets/port-5060-udp-sip.txt
set RPORT 5060
run
back
```

### SMB — 445/tcp (and 139/tcp)

```text
use auxiliary/scanner/smb/smb_version
set RHOSTS file:targets/port-445-tcp-smb.txt
set RPORT 445
run
back
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS file:targets/port-445-tcp-smb.txt
set RPORT 445
run
back
use auxiliary/scanner/smb/smb_enumusers
set RHOSTS file:targets/port-445-tcp-smb.txt
set RPORT 445
run
back
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS file:targets/port-445-tcp-smb.txt
set RPORT 445
run
back
```

For hosts with only 139 open, use `port-139-tcp-smb.txt` and `RPORT 139`.

### SMTP — 25/tcp

```text
use auxiliary/scanner/smtp/smtp_version
set RHOSTS file:targets/port-25-tcp-smtp.txt
set RPORT 25
run
back
```

User enumeration (`smtp_enum`) and open relay are **not** here — they guess
usernames / ask the server to relay mail, so they're in
[MANDATORY_CHECKS.md → Risky checks](MANDATORY_CHECKS.md#3-risky-checks).

### SNMP — 161/udp

```text
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS file:targets/port-161-udp-snmp.txt
set RPORT 161
run
back
```

`COMMUNITY` defaults to `public`; output here = default community string.

### SSL/TLS — TLS-wrapped ports (443, 8443, 993, …)

```text
# extra — not in the automatic run
use auxiliary/scanner/ssl/ssl_version
set RHOSTS file:targets/port-<PORT>-tcp-ssl.txt
set RPORT <PORT>
run
back
# extra — not in the automatic run
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS file:targets/port-<PORT>-tcp-ssl.txt
set RPORT <PORT>
run
back
# extra — not in the automatic run
use auxiliary/scanner/ssl/openssl_ccs
set RHOSTS file:targets/port-<PORT>-tcp-ssl.txt
set RPORT <PORT>
run
back
```

`ssl_version` reports deprecated protocols, weak / RC4 / export ciphers,
POODLE, BEAST, LOGJAM, and expired or self-signed certificates.

> [!WARNING]
> `ssl_version` and `openssl_ccs` only speak raw TLS. For **STARTTLS**
> services (SMTP 25, Postgres 5432, FTP, IMAP, POP3, LDAP, MySQL) use the
> nmap / sslscan checks — ReconFlow's recon runs them; see
> [MANUAL_VERIFICATION.md → SSL/TLS](../reference/MANUAL_VERIFICATION.md#ssltls).
> `openssl_heartbleed` can do STARTTLS: `set TLS_CALLBACK SMTP` (or `IMAP`,
> `POP3`, `FTP`, `POSTGRES`).

### SSH — 22/tcp

```text
use auxiliary/scanner/ssh/ssh_version
set RHOSTS file:targets/port-22-tcp-ssh.txt
set RPORT 22
run
back
```

### Telnet — 23/tcp

```text
use auxiliary/scanner/telnet/telnet_version
set RHOSTS file:targets/port-23-tcp-telnet.txt
set RPORT 23
run
back
```

### VNC — 5900/tcp

```text
use auxiliary/scanner/vnc/vnc_none_auth
set RHOSTS file:targets/port-5900-tcp-vnc.txt
set RPORT 5900
run
back
```

### Web — any web port

```text
use auxiliary/scanner/http/http_version
set RHOSTS file:targets/port-<PORT>-tcp-web.txt
set RPORT <PORT>
# https ports only
set SSL true
run
back
use auxiliary/scanner/http/title
set RHOSTS file:targets/port-<PORT>-tcp-web.txt
set RPORT <PORT>
# https ports only
set SSL true
run
back
```

### WinRM — 5985/tcp (5986 with TLS)

```text
use auxiliary/scanner/winrm/winrm_auth_methods
set RHOSTS file:targets/port-5985-tcp-winrm.txt
set RPORT 5985
run
back
```

### X11 — 6000/tcp

```text
use auxiliary/scanner/x11/open_x11
set RHOSTS file:targets/port-6000-tcp-x11.txt
set RPORT 6000
run
back
```

---

## 3. After the run

- `spool off`, then rebuild the report — it never touches a target. If a
  log or evidence file ended up in your current, parent or home folder, it
  prints the `mv` to fix it:

  ```bash
  python3 report.py <recon-folder>
  ```

  Your `[+]` results appear under *Detected by: Metasploit (manual)*, with
  the matching log lines quoted in `vulnerabilities/`. Lines no rule
  recognises are listed under *Other Metasploit output* for you to review.
- `vulns`, `creds` and `loot` list what modules stored in the database.

---

## 4. What Metasploit alone misses

If you test with Metasploit only (without ReconFlow's recon), these have no
Metasploit scanner — ReconFlow's recon covers them, so after a ReconFlow run
they're already in `FINDINGS.md`:

| Check | Command |
|---|---|
| Ruby DRb, distccd, UnrealIRCd, r-services | `nmap -Pn -sV -pPORT TARGET` (`--script irc-info` for IRC) |
| JDWP debug port | `nmap -Pn -pPORT --script jdwp-version TARGET` |
| NFS root / writable exports | `nmap -Pn -p111,2049 --script nfs-showmount,nfs-ls TARGET` |
| SMB anonymous share access level | `nmap -Pn -pPORT --script smb-enum-shares TARGET` |
| Anonymous kubelet / Kubernetes API | `curl -sk https://TARGET:10250/pods` · `curl -sk https://TARGET:6443/api/v1/namespaces` |
| TLS on STARTTLS services (SMTP, Postgres, FTP, IMAP, POP3, LDAP, MySQL) | `nmap -Pn -pPORT --script ssl-enum-ciphers,ssl-cert,ssl-poodle,ssl-dh-params TARGET` · `sslscan --starttls-smtp TARGET:25` |
| Anonymous / weak DH key exchange | `nmap -Pn -pPORT --script ssl-dh-params TARGET` |
| SSH weak algorithms | `ssh-audit -p PORT TARGET` |

---

## 5. Then: the mandatory checks

Finish with [MANDATORY_CHECKS.md](MANDATORY_CHECKS.md): safe manual checks
first, then the dangerous ones — risky checks, credential testing, exploit
confirmations and other intrusive steps. Neither ReconFlow nor this runbook
runs any of the dangerous ones.
