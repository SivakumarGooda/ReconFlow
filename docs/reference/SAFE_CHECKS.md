# Safe Checks — what `safechecks.py` runs

> **Reference — not a step.** The step is [MANDATORY_CHECKS.md → 1. Safe checks](../workflow/MANDATORY_CHECKS.md#1-safe-checks--already-run-by-reconflowpy). This page is for looking up what each safe check does, and for re-running one by hand.

> [!WARNING]
> **Authorized engagements only.**

**`reconflow.py` runs these checks by itself** at the end of every run
(after the per-port checks), against every host, on every port the service
was found on. `safechecks.py` is the same code on its own — for re-running
them later on a finished output folder (e.g. with `--domain` you didn't
know at scan time). They only **read** what a service already
shows: no guessed logins, no brute force, no exploits, no writes. The
dangerous checks are in [MANDATORY_CHECKS.md → Part 2](../workflow/MANDATORY_CHECKS.md#part-2--dangerous-checks-never-automated)
and are never run by it.

## Contents

- [Running it](#running-it)
- [What it saves](#what-it-saves)
- [Re-running one check by hand](#re-running-one-check-by-hand)
- [The checks, per service](#the-checks-per-service)

---

## Running it

During a scan — nothing to do; add these to `reconflow.py` if needed:

| `reconflow.py` option | Does |
|---|---|
| `--domain NAME` | adds the DNS zone transfer for that domain (repeat for several) |
| `--with-data` | adds the CouchDB / Elasticsearch document samples — real data, only if in scope |
| `--testssl` | adds a full `testssl.sh` audit per TLS port (slow) |
| `--no-safe-checks` | skips the safe checks altogether |

Later, on a finished output folder:

```bash
sudo python3 safechecks.py <recon-folder>                     # all default checks
sudo python3 safechecks.py <recon-folder> --dry               # show what would run, run nothing
python3 safechecks.py <recon-folder> --list                   # list every check
sudo python3 safechecks.py <recon-folder> --domain corp.example   # + DNS zone transfer
sudo python3 safechecks.py <recon-folder> --only smb-browse,ldap-dump
```

| Option | Does |
|---|---|
| `--dry` | prints every check and the host:ports it would hit — runs nothing |
| `--list` | lists all checks (name, service, what it does, condition) |
| `--domain NAME` | adds the DNS zone transfer for that domain (repeat for several) |
| `--with-data` | adds the CouchDB / Elasticsearch document samples — real data, only if in scope |
| `--testssl` | adds a full `testssl.sh` audit per TLS port (slow) |
| `--only A,B` | runs only the named checks |
| `--threads N` | parallel checks (default 8) |
| `-y` | don't ask before starting |

Run it **with sudo** for the NFS mount and iSCSI checks; without root they
are skipped and listed. A check whose tool isn't installed is skipped and
listed too. It asks before it starts (unless `-y`), and Ctrl-C stops every
running check.

## What it saves

| File | What |
|---|---|
| `evidence/<check>_<ip>_<port>_1.txt` | one file per host and check — the command on the first line, then its output |
| `evidence/searchsploit.txt`, `evidence/rpc-coercion.txt` | the two checks that only read files on disk |
| `SAFE-CHECKS.md` | the index: what ran on how many hosts, **every file it saved**, which ones look like a hit (⚠️), what to look for, and what was skipped and why |

Then the report: results a rule recognises (✅ below) are marked
**Confirmed** by themselves. Results only a person can judge (✍️) that
**look like a problem** are listed in `FINDINGS.md` → **Safe checks —
possible issues**, one row per host with the evidence file and what to look
for (and counted under *Manual follow-up*). Open each; if it is a real
issue, add it under *3. New findings* in `manual-checklist.md`. That list
is worked out again from the evidence files on every rebuild.

## Re-running one check by hand

Every check below also works with the `each` helper — e.g. to repeat it
for one service, or with different settings. Load the helpers first, in
the output folder:

```bash
cd <recon-folder>
source /path/to/ReconFlow/tools/rf-helpers.sh
```

How the helpers work: [MANDATORY_CHECKS.md → Before you start](../workflow/MANDATORY_CHECKS.md#before-you-start--run-on-every-target).

---

## The checks, per service

Each section: what `safechecks.py` runs for that service, the same check as
an `each` command (to re-run one, or change it — e.g. other TFTP file names,
a STARTTLS testssl), what a finding looks like, and whether the report
recognises it by itself (✅) or you judge it (✍️).

### Any service — map versions to known CVEs

**In `safechecks.py`:** `searchsploit` — runs by default (reads the scan files only, no traffic)

```bash
searchsploit --nmap scan-tcp.xml | tee evidence/searchsploit-tcp.txt
[ -f scan-udp.xml ] && searchsploit --nmap scan-udp.xml | tee evidence/searchsploit-udp.txt
```

A finding when a version you found is a known vulnerable release — confirm
against the vendor advisory before reporting.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### DNS — zone transfer

**In `safechecks.py`:** `dns-axfr` — only with `--domain corp.example` (repeat for several domains)

Needs the domain name (from the client, `ldap-rootdse`, certificates or
`smb-os-discovery` output):

```bash
export DOMAIN=corp.example
RF_DRY=1 each dns-axfr tcp-dns 'dig axfr @$T -p $P $DOMAIN +time=5 +tries=1'
each dns-axfr tcp-dns 'dig axfr @$T -p $P $DOMAIN +time=5 +tries=1'
cat evidence/dns-axfr_*
```

The first `each` line only previews the hosts and ports; the second runs it.
`tcp-dns` because a zone transfer always uses TCP (with `dns` a host found
on both TCP and UDP 53 would be asked twice). If DNS was only found over UDP,
use `udp-dns` — `dig axfr` still connects over TCP.

A finding when the full record list comes back (`XFR size: … records`);
`Transfer failed.` = refused. No rule recognises a zone transfer, so add a
successful one as a block under *3. New findings* in `manual-checklist.md`
(`Evidence: evidence/dns-axfr_<ip>_53_1.txt`), then rebuild the report.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### TFTP — read a config file (TFTP has no authentication)

**In `safechecks.py`:** `tftp-get` — runs by default (tries the four file names below)

Tries a few likely file names; add the device's own (e.g. from its model):

```bash
export TFTP_FILES="startup-config running-config config.txt boot.ini"
each tftp-get tftp 'cd "$(mktemp -d)" && for f in $TFTP_FILES; do tftp $T $P -c get $f 2>/dev/null; [ -s $f ] && echo "GOT $f ($(wc -c < $f) bytes) in $PWD"; done; true'
```

A finding when a file downloads (`GOT …`).

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### Finger — ask about users

**In `safechecks.py`:** `finger-users` — runs by default

```bash
each finger-users finger 'echo root | nc -w 5 $T $P; echo; echo | nc -w 5 $T $P'
```

A finding when user details or a logged-in list come back.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### NFS — mount every export read-only and look inside

**In `safechecks.py`:** `nfs-mount` — only when run as root (`sudo python3 safechecks.py …`)

Needs root for `mount` (`sudo -v` first):

```bash
each nfs-mount rpcbind 'for e in $(showmount -e --no-headers $T 2>/dev/null | cut -d" " -f1); do d=$(mktemp -d); if sudo mount -t nfs -o ro,nolock,soft,timeo=50 "$T:$e" "$d" </dev/null; then echo "## $T:$e"; ls -la "$d" | head -40; sudo umount "$d"; fi; rmdir "$d"; done'
```

A finding when data is readable or `/` is exported. `no_root_squash` can't
be seen read-only — check it under section 6 *Write-access tests* if in
scope.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### SMB — browse every readable share

**In `safechecks.py`:** `smb-browse` — runs by default

Lists each host's disk shares anonymously, then `ls` in each (hosts with
both 139 and 445 are listed twice — harmless):

```bash
each smb-browse smb 'smbclient -N -L //$T -p $P -g 2>/dev/null </dev/null | grep "^Disk|" | cut -d"|" -f2 | while read -r s; do echo "## $s"; smbclient -N "//$T/$s" -p $P -c "ls" </dev/null 2>&1 | head -40; done'
```

A finding when a share lists files without credentials. To keep a sample
file as evidence, `get` it by hand from the share you care about.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### SMB / MSRPC — relay (coercion) surface

**In `safechecks.py`:** `rpc-coercion` — runs by default (reads recon output only, no traffic)

Already in the recon output — this just pulls it out, per host:

```bash
awk '/^===== /{h=$2} /MS-RPRN|MS-EFSR|MS-DFSNM|MS-FSRVP/{print h": "$0}' service-checks/port-*-msrpc.txt 2>/dev/null | sort -u | tee evidence/rpc-coercion.txt
```

A finding when coercion endpoints are exposed — **don't trigger them**.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### LDAP — dump each naming context anonymously

**In `safechecks.py`:** `ldap-dump` — runs by default

Takes the naming contexts from the rootDSE, then reads up to 50 entries of
each:

```bash
each ldap-dump ldap 'S=ldap; { [ $P = 636 ] || [ $P = 3269 ]; } && S=ldaps; for nc in $(ldapsearch -x -H $S://$T:$P -s base -b "" namingContexts 2>/dev/null | sed -n "s/^namingContexts: //p"); do echo "## $nc"; ldapsearch -x -H $S://$T:$P -b "$nc" -z 50 2>&1 | head -200; done'
```

A finding when directory entries (users, groups) come back.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### IKE — main-mode handshake

**In `safechecks.py`:** `ike-main` — runs by default

```bash
each_file ike-main ike 'ike-scan -M --sport=0 --dport=$P -f $F'
```

Lists transforms and vendor IDs per host — a finding for weak transforms
(DES, MD5, DH group 1/2).

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### iSCSI — target discovery

**In `safechecks.py`:** `iscsi-disc` — only when run as root

```bash
each iscsi-disc iscsi 'iscsiadm -m discovery -t st -p $T:$P'
```

A finding when targets are listed without CHAP.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### Cassandra — anonymous login

**In `safechecks.py`:** `cql-anon` — runs by default (needs `cqlsh`)

```bash
each cql-anon cassandra 'cqlsh $T $P --connect-timeout=10 -e "DESCRIBE KEYSPACES"'
```

A finding when keyspaces are listed.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### MongoDB — anonymous access

**In `safechecks.py`:** `mongo-anon` — runs by default (needs `mongosh`)

```bash
each mongo-anon mongodb 'mongosh --host $T --port $P --quiet --eval "db.adminCommand({listDatabases:1}).databases.map(d => d.name)"'
```

A finding when databases are listed.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### CouchDB / Elasticsearch — look at the exposed data

**In `safechecks.py`:** `couch-peek`, `es-peek` — only with `--with-data` (they read real documents)

Reads 5 documents per database / index — **note names only as evidence**,
don't copy personal data:

```bash
each couch-peek couchdb 'U=http://$T:$P; curl -s -m 5 $U/ >/dev/null || U=https://$T:$P; for d in $(curl -sk -m 10 $U/_all_dbs | tr -d "[]\"" | tr "," " " | head -c 2000); do echo "## $d"; curl -sk -m 10 "$U/$d/_all_docs?limit=5"; echo; done'
each es-peek elasticsearch 'U=http://$T:$P; curl -s -m 5 $U/ >/dev/null || U=https://$T:$P; curl -sk -m 10 "$U/" | head -8; for i in $(curl -sk -m 10 "$U/_cat/indices?h=index" | head -20); do echo "## $i"; curl -sk -m 10 "$U/$i/_search?size=5"; echo; done'
```

A finding when personal data or secrets are readable.

> ✅ / ✍️ **Elasticsearch: by itself** (the `cluster_name` line). **CouchDB data and the documents themselves: report yourself** — add a *New findings* block if they hold personal data or secrets.

### Redis — config read

**In `safechecks.py`:** `redis-config` — runs by default

```bash
each redis-config redis 'redis-cli -h $T -p $P info server | head -5; redis-cli -h $T -p $P config get dir; redis-cli -h $T -p $P info keyspace'
```

A finding when it answers without AUTH (**don't write keys**).

> ✅ **Goes into the report by itself.** `report.py` reads this output; when it shows the problem, the finding is marked **Confirmed**. (`redis_version:` = no AUTH). What `config get dir` reveals: report yourself.

### MQTT — read every topic (10 seconds per broker)

**In `safechecks.py`:** `mqtt-topics` — runs by default (needs `mosquitto_sub`)

```bash
each mqtt-topics mqtt 'mosquitto_sub -h $T -p $P -t "#" -v -W 10 2>&1 | head -50'
```

A finding when messages arrive.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### Docker — list containers

**In `safechecks.py`:** `docker-ps` — runs by default

```bash
each docker-ps docker 'U=http://$T:$P; curl -s -m 5 $U/version >/dev/null || U=https://$T:$P; curl -sk -m 10 "$U/version"; echo; curl -sk -m 10 "$U/containers/json?all=1"'
```

A finding when the container list comes back (**don't start any**).

> ✅ **Goes into the report by itself.** `report.py` reads this output; when it shows the problem, the finding is marked **Confirmed**. (`ApiVersion` = open API). The container list itself: report yourself.

### etcd — list keys

**In `safechecks.py`:** `etcd-keys` — runs by default (needs `etcdctl`)

```bash
each etcd-keys etcd 'curl -s -m 10 http://$T:$P/version; echo; ETCDCTL_API=3 etcdctl --endpoints=http://$T:$P --command-timeout=10s get / --prefix --keys-only | head -100'
```

A finding when key names come back.

> ✅ **Goes into the report by itself.** `report.py` reads this output; when it shows the problem, the finding is marked **Confirmed**. (`etcdserver` = no auth). The key names: report yourself.

### Kubernetes API — anonymous permissions

**In `safechecks.py`:** `k8s-anon` — runs by default

```bash
each k8s-anon kubernetes 'curl -sk -m 10 https://$T:$P/apis | head -40; echo; curl -sk -m 10 https://$T:$P/api/v1/namespaces | head -40'
```

A finding when anything beyond `401` / `403` comes back — then review RBAC
for `system:anonymous`.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### rsync — list every module

**In `safechecks.py`:** `rsync-list` — runs by default

```bash
each rsync-list rsync 'for m in $(rsync --list-only --timeout=20 rsync://$T:$P/ </dev/null | cut -f1 | tr -d " "); do echo "## $m"; rsync --list-only --timeout=20 "rsync://$T:$P/$m/" </dev/null 2>&1 | head -30; done'
```

A finding when files are listed without auth.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### NNTP — list groups

**In `safechecks.py`:** `nntp-list` — runs by default

```bash
each nntp-list nntp 'printf "LIST\r\nQUIT\r\n" | nc -w 5 $T $P | head -50'
```

A finding when groups are listed without auth.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### SVN — read history

**In `safechecks.py`:** `svn-log` — runs by default

```bash
each svn-log svn 'svn log --non-interactive -l 20 svn://$T:$P/'
```

A finding when the commit log comes back.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### RTSP — open the stream

**In `safechecks.py`:** `rtsp-probe` — runs by default (needs `ffprobe`)

Probes the stream without a player (cameras often need a path such as
`/live` or `/stream1` — try the vendor's):

```bash
each rtsp-probe rtsp 'ffprobe -v error -rw_timeout 10000000 -rtsp_transport tcp -show_streams rtsp://$T:$P/ 2>&1 | head -30'
```

A finding when stream details come back without auth. To *watch* it:
`ffplay rtsp://TARGET:PORT/` for the host you want.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### UPnP — device description

**In `safechecks.py`:** `upnp-desc` — runs by default

Fetches each device's description URL found by recon (only URLs on the
device itself):

```bash
each upnp-desc upnp 'for u in $(grep -ho "http://$T:[0-9]*/[^ ]*" service-checks/port-*-upnp.txt 2>/dev/null | sort -u); do echo "## $u"; curl -s -m 10 "$u" | head -60; done'
```

A finding when model, firmware or services are listed.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### CUPS — admin page

**In `safechecks.py`:** `cups-admin` — runs by default

```bash
each cups-admin ipp 'curl -s -m 10 -o /dev/null -w "%{http_code} /admin\n" http://$T:$P/admin'
```

A finding when `/admin` answers `200`.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### Zookeeper — cluster info

**In `safechecks.py`:** `zk-info` — runs by default

```bash
each zk-info zookeeper 'for c in srvr dump; do echo "## $c"; echo $c | nc -w 5 $T $P; done'
```

A finding when stats / sessions come back without auth.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).

### RDP — NLA and the login screen

**In `safechecks.py`:** `rdp-nla` — runs by default (the NLA line; the screenshot line is by hand)

```bash
each_file rdp-nla rdp 'nxc rdp $F --port $P'
each_file rdp-shot rdp 'nxc rdp $F --port $P --nla-screenshot'
```

A finding when `nla:False` — the second line saves a screenshot of the
login screen for each such host (in `~/.nxc/screenshots/`). **Don't log
in.**

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)). The screenshots are in `~/.nxc/screenshots/` — copy the ones you use into `evidence/`.

### X11 — display info

**In `safechecks.py`:** `x11-info` — runs by default

```bash
each x11-info x11 'xdpyinfo -display $T:$((P - 6000)) 2>&1 | head -30'
```

A finding when display details come back (`name of display:` — this
confirms *X11 server allows unauthenticated access* automatically).

> ✅ **Goes into the report by itself.** `report.py` reads this output; when it shows the problem, the finding is marked **Confirmed**.

### Web — exposed files on every web port

**In `safechecks.py`:** `web-exposed` — runs by default (browsing the apps stays by hand)

A handful of requests per port, both schemes. A `200` is a lead, not proof
— open it and check the content (some sites answer `200` for everything):

```bash
each web-exposed web 'for s in http https; do for p in /.git/HEAD /.svn/entries /.env /.DS_Store /server-status /phpinfo.php /backup.zip /backup.tar.gz; do c=$(curl -sk -m 8 -o /dev/null -w "%{http_code}" "$s://$T:$P$p"); [ "$c" = 200 ] && echo "200 $s://$T:$P$p"; done; done; true'
```

**Then by hand** (judgement, can't be looped): open both `http://` and
`https://` of each port from `web-report.html` — admin panels, directory
listings, verbose errors.

> ✍️ **You must report this yourself.** The output is saved in `evidence/`, but the report can't understand it. Read it — if it shows a problem, add it under *3. New findings* in `manual-checklist.md` ([how](../workflow/MANDATORY_CHECKS.md#how-to-record-results)).
>
> ⛔ **Browsing by hand is not saved at all** — screenshot what you find into `evidence/` and add a *New findings* block.

### SSL/TLS — full audit + proof of old protocols

**In `safechecks.py`:** `tls-old` — runs by default; `testssl` — only with `--testssl` (slow)

```bash
RF_TIMEOUT=600 each testssl ssl 'testssl.sh --quiet --color 0 $T:$P'
each tls-old ssl 'for v in -ssl3 -tls1 -tls1_1; do echo "## $v"; echo | openssl s_client -connect $T:$P $v 2>&1 | grep -E "^New,|alert|no protocols"; done'
```

`testssl.sh` covers STARTTLS too: add `--starttls smtp` (or `ftp`, `imap`,
`pop3`, `ldap`, `postgres`, `mysql`) and use that service as the source,
e.g. `each testssl-smtp smtp 'testssl.sh --quiet --color 0 --starttls smtp $T:$P'`.
A `New, TLSv1, Cipher is <cipher>` line in `tls-old` output (or SSLv3 /
TLSv1.1) confirms *Deprecated SSL/TLS protocol versions* automatically.
`New, (NONE), Cipher is (NONE)` means the server refused it — openssl still
prints `Protocol : TLSv1` then, so don't go by that line.

> ✅ / ✍️ **`tls-old`: by itself** (a `New, TLSv1, Cipher is …` line confirms *Deprecated SSL/TLS protocol versions*). **`testssl.sh`: report yourself** — the report can't read its output.
