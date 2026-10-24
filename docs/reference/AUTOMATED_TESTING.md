# Automated Testing Playbook

> **Reference — not a step.** What automation runs, for looking up. The steps are in [the whole picture](../README.md).

> [!WARNING]
> **Authorized engagements only.** Every command assumes written permission to
> test the target.

The reference for what ReconFlow does **on its own**, from the scope files to
`FINDINGS.md` in the output folder (`-o`, created if missing), and how the
generated `metasploit.rc` works.

> [!IMPORTANT]
> This page is the *covered* half. What automation deliberately leaves out —
> risky checks, credential testing, exploits, other intrusive steps — is in
> [MANDATORY_CHECKS.md](../workflow/MANDATORY_CHECKS.md). Read it after every run.

## Contents

- [The workflow](#the-workflow)
- [What runs on its own](#what-runs-on-its-own)
- [What comes back to you](#what-comes-back-to-you)
- [The generated metasploit.rc](#the-generated-metasploitrc)
- [Per-port reference](#per-port-reference)
- [Web ports](#web-ports)

---

## The workflow

Scan once, import into the Metasploit database, and let the DB feed RHOSTS to
every module — you never paste IPs.

### 1. Set the scope

Targets go in `scope/inscope_ips.txt`, exclusions in `scope/outofscope_ips.txt`:

```text
# inscope_ips.txt          # outofscope_ips.txt
10.0.0.0/24                10.0.0.1
192.168.1.0/24             192.168.1.200-220
172.16.5.10-50
```

Out-of-scope hosts go to nmap as `--excludefile` and are filtered out again
before any check, screenshot or Metasploit module runs. If one still appears
in the scan data (for example with `--from-xml`), it is ignored, deleted from
the msf workspace after import, and noted in the report. With `--from-xml`,
hosts in the XML that the in-scope list doesn't cover are dropped the same
way.

> [!IMPORTANT]
> **Out of scope: use IPs, not hostnames.** nmap excludes only the first
> address a hostname resolves to, and ReconFlow's re-check relies on reverse
> DNS matching the name. List the IPs / CIDRs / ranges instead
> ([README → Scope files](../../README.md#scope-files)).

### 2. Start the msf database (once per machine)

```bash
sudo msfdb init    # or: sudo msfdb run
```

### 3. Run it

```bash
sudo python3 reconflow.py -o recon-clientA    # all TCP ports + top 100 UDP
```

ReconFlow asks two questions up front: **Proceed with recon?** (scan + safe
checks) and **Also run the Metasploit modules automatically?** Answer **y** to
both and everything below runs on its own. Risky checks never run — they're
listed for you (see [What comes back to you](#what-comes-back-to-you)).
Unattended: `-y --msf`.

The equivalent raw nmap commands — the TCP scan in two phases, a fast
sweep of every port, then detection on the open ones only:

```bash
# phase 1: which ports are open
nmap -iL scope/inscope_ips.txt --excludefile scope/outofscope_ips.txt \
     -p- -sS --open -T4 -oA scan-tcp-ports
# phase 2: hosts and ports found open in phase 1
nmap -iL scan-tcp-hosts.txt -Pn -p <open ports> -sS -O -sV \
     --script "default and not http-open-proxy" --open -T4 -oA scan-tcp
nmap -iL scope/inscope_ips.txt --excludefile scope/outofscope_ips.txt \
     -sU -sV --open --top-ports 100 -T4 -oA scan-udp
```

`-oA` writes `.nmap`, `.xml` and `.gnmap` for each scan. nmap's default
scripts run without `http-open-proxy` (a default script, but a risky check).
`--quick` limits TCP to the top 1000 ports in a single scan and `--no-udp`
skips UDP — both are faster, and both are noted in the report. `--pn` adds
`-Pn` so hosts that don't answer ping are scanned too.

### 4. Metasploit

If you answered **y** to the Metasploit question (or passed `--msf`), the
script runs `metasploit.rc` itself when `msfconsole` is installed and the
database answers `db_status`. Otherwise `FINDINGS.md` says so under
*Manual follow-up*; run it yourself:

```bash
cd recon-clientA                # the -o folder
msfconsole -r metasploit.rc    # imports the scan XML and runs everything
```

Or go module by module with [MANUAL_METASPLOIT.md](../workflow/MANUAL_METASPLOIT.md).
The rc imports each scan XML by
absolute path, so it also works with `--from-xml` files that live outside the
output folder.

---

## What runs on its own

For **every open port** the script looks up a per-service playbook and:

1. **Runs enumeration commands** against that exact port — nmap NSE,
   smbclient, snmpwalk, ldapsearch, curl / whatweb on http **and** https, and
   more — in parallel (`--threads`, `--check-timeout`). Output goes to
   `service-checks/port-<n>-<proto>-<svc>.txt`.
2. **Writes every command** to `service-checks/commands.sh` so any of them can
   be re-run by hand.
3. **Runs the matching Metasploit modules** from the database (see
   [below](#the-generated-metasploitrc)).
4. **Runs SSL/TLS checks** on every TLS port **and** every STARTTLS service
   (SMTP, FTP, IMAP, POP3, LDAP, Postgres, MySQL) that offers TLS — nmap's
   `ssl-cert` script in the scan tells which do: nmap `ssl-enum-ciphers`,
   `ssl-cert`, `sslv2`, `ssl-heartbleed`, `ssl-poodle`, `ssl-ccs-injection`,
   `ssl-dh-params`, plus `sslscan`.
5. **Matches version strings** against known-bad releases: vsftpd 2.3.4,
   ProFTPD 1.3.3c, UnrealIRCd, Samba 3.0.20–3.0.25, distccd, bind shells, DRb,
   Java RMI, JDWP, Telnet, r-services.
6. **Parses all check output** for: anonymous FTP · SMB null session /
   anonymous shares / signing · SMTP VRFY · open X11 · DNS open recursion · NFS exports, root (`/`) exports
   and writable exports · default SNMP community · unauthenticated Redis /
   Docker / Elasticsearch / CouchDB / etcd / kubelet / MQTT ·
   NSE `State: VULNERABLE` · old TLS protocols, weak ciphers, expired /
   self-signed certificates.
7. **Runs the safe manual checks** (`safechecks.py`, details in
   [SAFE_CHECKS.md](SAFE_CHECKS.md)) on every target — read-only steps such
   as share and directory listings, anonymous database access and exposed
   web files. Output goes to `evidence/`; results that may be an issue are
   listed in `FINDINGS.md` → *Safe checks — possible issues*. Skip with
   `--no-safe-checks`.
8. **Saves `results.json` and builds the report** with `report.py` (the
   same code you re-run later — see [README → Reporting](../../README.md#reporting)):
   `FINDINGS.md`, the `vulnerabilities/` folder (one file per finding, with
   the evidence lines), and `manual-checklist.md` for the hand-run checks.
   `FINDINGS.md` has:
   - a summary table by severity (Critical → Info) with every affected IP:port
   - nmap results for **every** IP (port, service, version, OS, which findings
     apply)
   - one section per finding: why it matters, all affected hosts with their
     evidence file, **copy-paste reproduce commands per IP**, expected output,
     next steps, fix, and a Metasploit reference where one exists (never run)
   - *Manual follow-up*: everything the automation could not do
9. **Tells you what's next:** run the checklist / your own Metasploit session
   if you want, then `python3 report.py <folder>` to fold the results in.

The by-hand guides are fixed docs in the ReconFlow folder, not regenerated per
run: [MANDATORY_CHECKS.md](../workflow/MANDATORY_CHECKS.md) (what automation never runs),
[MANUAL_METASPLOIT.md](../workflow/MANUAL_METASPLOIT.md) (this Metasploit run, by hand)
and [MANUAL_VERIFICATION.md](MANUAL_VERIFICATION.md) (checks per service).

---

## What comes back to you

Anything the automation **could not** do is printed at the end under
`MANUAL CHECK REQUIRED` and listed in `FINDINGS.md` → *Manual follow-up*:

| Item | Why it's listed |
|---|---|
| Possible issues from the safe checks | results only a person can judge — listed in their own `FINDINGS.md` section with a command to reproduce |
| Safe checks skipped | tool missing, needs root, or needs an option (`--domain`, `--with-data`, `--testssl`) — with the command to run just those later |
| Manual checklist not done yet | entries in `manual-checklist.md` with no answer and no evidence |
| **Risky checks not run** | listed first, per host: MySQL empty password, SMTP open relay, SMTP user enumeration, open HTTP proxy, RMI class loading — run them by hand if in scope ([MANDATORY_CHECKS.md](../workflow/MANDATORY_CHECKS.md#3-risky-checks)) |
| **Credential testing not done** | login services found (FTP, SSH, SMB, …) — never tested automatically ([MANDATORY_CHECKS.md](../workflow/MANDATORY_CHECKS.md#4-credential-testing)) |
| Metasploit modules not run | you answered **N** — run `metasploit.rc` or the runbook yourself |
| Tools not installed | with the exact commands that were skipped |
| Checks that timed out or returned nothing | re-run them by hand |
| nmap checks with no script output | usually means not vulnerable / not applicable |
| UDP checks skipped without root | listed ready to run with `sudo` |
| Metasploit not run, or modules that failed to load | no msfconsole / database down |
| Screenshots not captured | open the URLs in a browser instead |
| Services with no automation at all | see `needs-attention/` below |
| Hosts up with no open ports | with the follow-up nmap commands |
| Addresses that didn't answer host discovery | not scanned; re-run with `--pn` if live hosts may block ping |
| STARTTLS services with no TLS | nmap's `ssl-cert` saw no certificate, so the TLS checks were skipped (cleartext login is the finding) |
| Out-of-scope hosts found in the scan data | ignored; nothing was run against them |
| Scan limits | no root (no OS / UDP), `--quick` (top 1000 TCP only) or `--no-udp` |

### Services with no automation → `needs-attention/`

Not every service has a clean automated path (odd ports, `unknown`,
`tcpwrapped`, r-services, etc.). Rather than let those slip, the script writes
a `needs-attention/` folder: one file per port
(`port-<n>-<proto>-<name>.txt`) listing the affected IPs and the nmap version
detail, plus a `SUMMARY.txt`. These are the ports the automation deliberately
did not touch — work through them by hand.

---

## The generated metasploit.rc

```text
# capture everything to a file
spool '<outdir>/msf-run.log'
# a new workspace for every run: <folder>_<date>_<time>
workspace -a <name>
workspace <name>
# one line per scan (tcp, udp)
db_import '<abs>/scan-tcp.xml'
db_import '<abs>/scan-udp.xml'
# out of scope — only if one is in the imported XML
hosts -d 10.0.0.1
hosts
services
setg THREADS 10

# then, port by port:
use auxiliary/scanner/ftp/ftp_version
# RHOSTS = every DB host with 21 open
services -u -p 21 -R
set RPORT 21
run
back
# ... every other module / port
```

- **`services -u -p <port> -R` is the key:** `-R` sets RHOSTS from the DB
  query, so each module targets exactly the hosts that have that port open.
- **One workspace per run:** the name carries the run's date and time, so a
  re-run into the same folder starts from an empty workspace and can never
  target a host an earlier run imported. `msf-manual.rc` from the same run
  uses the same workspace.
- **Different services on one port:** if a port runs different services on
  different hosts, the rc adds `-s <name>` so each module only hits the right
  hosts.
- **Same port on TCP and UDP:** msf's `services` can't filter by protocol, so
  a port open over both (e.g. 161) gets one block per protocol with
  `set RHOSTS <exact IPs>` instead.
- **Paths are quoted**, so output folders with spaces work.
- All output is spooled to `msf-run.log`; every `[+]` line is copied to
  `msf-findings.txt` and into `FINDINGS.md`.

### Credential modules — never run

The rc lists a login module per port but **commented out**, so the automatic
run never tries a login. Ready-to-paste blocks per service are in
[MANDATORY_CHECKS.md → Credential testing](../workflow/MANDATORY_CHECKS.md#4-credential-testing).

### Doing it by hand

Step by step, with every module per service:
[MANUAL_METASPLOIT.md](../workflow/MANUAL_METASPLOIT.md).

---

## Per-port reference

### Metasploit modules

The last column is **never run** — see
[MANDATORY_CHECKS.md](../workflow/MANDATORY_CHECKS.md#4-credential-testing).

| Port | Service | Modules run automatically | Login module (never run) |
|---|---|---|---|
| 21 | FTP | `ftp_version`, `ftp_anonymous` | `ftp_login` |
| 22 | SSH | `ssh_version` | `ssh_login` |
| 23 | Telnet | `telnet_version` | `telnet_login` |
| 25 | SMTP | `smtp_version` | — |
| 110 / 143 | POP3 / IMAP | `pop3_version` / `imap_version` | — |
| 111 | RPC / NFS | `nfsmount` | — |
| 135 | MSRPC | `endpoint_mapper` | — |
| 161/udp | SNMP | `snmp_enum` | `snmp_login` |
| 445 | SMB | `smb_version`, `smb_enumshares`, `smb_enumusers`, `smb_ms17_010` | `smb_login` |
| 623/udp | IPMI | `ipmi_version`, `ipmi_cipher_zero` | — |
| 873 | rsync | `modules_list` | — |
| 1099 | Java RMI | `java_rmi_server` | — |
| 1433 | MSSQL | `mssql_ping` | `mssql_login` |
| 1521 | Oracle TNS | `tnslsnr_version` | — |
| 2375 | Docker API | `docker_version` | — |
| 3306 | MySQL | `mysql_version` | `mysql_login` |
| 3389 | RDP | `rdp_scanner` | — |
| 5060 | SIP | `sip/options` | — |
| 5432 | Postgres | `postgres_version` | `postgres_login` |
| 5900 | VNC | `vnc_none_auth` | `vnc_login` |
| 5985 / 5986 | WinRM | `winrm_auth_methods` | `winrm_login` |
| 6000 | X11 | `open_x11` | — |
| 6379 | Redis | `redis_server` | — |
| 27017 | MongoDB | — (NSE only) | `mongodb_login` |
| any web port | HTTP / HTTPS | `http_version`, `title` | — |

- DNS, LDAP, Elasticsearch and Memcached have no msf module in the rc but
  are covered by the CLI checks below. HTTP proxies get `http-headers` only;
  the open-proxy test is a risky check.
- IRC (6667) and AJP (8009) get NSE checks (`irc-info`, `ajp-methods` /
  `ajp-headers`). MySQL's `mysql-empty-password` is a risky check — listed,
  never run.
- Bind shells (1524) and distcc (3632) are flagged **Critical** in
  `FINDINGS.md` but never touched.
- r-services (512–514), `unknown`, `tcpwrapped` and anything unrecognised go
  to `needs-attention/`.

### Other checks (`service-checks/`)

Always run on the port the service was actually found on (FTP on 2121 →
`-p2121`). The full list lives in `PLAYBOOK` in `reconflow.py`; the exact
commands from a run are in `service-checks/commands.sh`. Highlights:

| Service | Commands |
|---|---|
| FTP | `nmap -Pn -pPORT --script ftp-anon,ftp-syst,ftp-bounce TARGET` |
| SSH | nmap `ssh2-enum-algos,ssh-hostkey,ssh-auth-methods` · `ssh-audit -p PORT TARGET` |
| SMTP | nmap `smtp-commands,smtp-ntlm-info` (`smtp-open-relay`, `smtp-enum-users`: listed, never run) |
| SMB | `enum4linux-ng -A TARGET` · `smbclient -N -L //TARGET/ -p PORT` · `nxc smb TARGET --port PORT -u '' -p '' --shares` · nmap `smb-os-discovery,smb-security-mode,smb2-security-mode,smb-enum-shares,smb-vuln-ms17-010` |
| SNMP | `snmpwalk -v2c -c public TARGET:PORT` (system, processes, users OIDs) |
| LDAP | `ldapsearch -x -H ldap[s]://TARGET:PORT -s base -b '' '*' +` · nmap `ldap-rootdse` |
| NFS / RPC | `rpcinfo -p TARGET` · `showmount -e TARGET` · nmap `nfs-showmount,nfs-ls,nfs-statfs` |
| DNS | nmap `dns-nsid,dns-recursion` · `dig @TARGET version.bind chaos txt` |
| MySQL | nmap `mysql-info` (`mysql-empty-password`: listed, never run) |
| Redis | `redis-cli -h TARGET -p PORT INFO server` |
| Docker | `curl -sk <scheme>://TARGET:PORT/version` |
| Elasticsearch | `curl -sk <scheme>://TARGET:PORT/_cat/indices?v` |
| rsync | `rsync --list-only rsync://TARGET:PORT/` |

Community-string guessing (`onesixtyone`) and other brute-style steps are
**not** automated; they are in
[MANDATORY_CHECKS.md → Other intrusive steps](../workflow/MANDATORY_CHECKS.md#6-other-intrusive-steps).

---

## Web ports

Any web port (80, 443, 8080, 8443, …) is probed over **both** http and https:

- screenshots of both schemes in `web-report.html`, with a link, status code,
  page title and redirect target for every URL probed
- `curl -I` and `whatweb` on both schemes
- nmap `http-title`, `http-headers`, `http-methods`, `http-robots.txt`
- the SSL/TLS checks above on TLS ports

If only one scheme answers, the other is not flagged. Heavier, noisier scans
(`nikto`, `nuclei`, `ffuf`) stay manual — see
[MANDATORY_CHECKS.md → Other intrusive steps](../workflow/MANDATORY_CHECKS.md#6-other-intrusive-steps).
