#!/usr/bin/env python3
"""
ReconFlow safe checks (safechecks.py) — Part 1 of MANDATORY_CHECKS, automated.

    sudo python3 safechecks.py <output folder>

reconflow.py runs these checks by itself at the end of every scan (skip with
--no-safe-checks). Run this script on its own only to re-run them later on
a finished output folder — e.g. with a --domain you didn't know at scan time.

Runs the SAFE manual checks from docs/workflow/MANDATORY_CHECKS.md (details:
docs/reference/SAFE_CHECKS.md) against every target: every host, on every
port the service was found on (targets/ in the output folder). Every check only
READS what a service already shows — no logins with guessed credentials, no
brute force, no exploits, no writes. The dangerous checks (Part 2) are never
run here.

  reads   targets/              the per-port host lists reconflow.py wrote
  writes  evidence/<check>_<ip>_<port>_1.txt   one file per host and check
          SAFE-CHECKS.md        what ran, every file it saved, which ones
                                look like a hit, and what to look for
          then rebuilds FINDINGS.md (report.py) — results a rule recognises
          become Confirmed findings; results that may be an issue are listed
          under "Safe checks — possible issues" with a command to reproduce

Only hosts in targets/ are touched — those already passed the scope and
out-of-scope filters of the ReconFlow run. Missing tools are skipped and
listed. USE ONLY ON SYSTEMS YOU ARE AUTHORIZED TO TEST.
"""

import argparse
import datetime as _dt
import glob
import ipaddress
import os
import re
import shlex
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reconflow as rf  # noqa: E402

# ---------------------------------------------------------------------------
# The checks. Each runs once per host:port with $T = IP and $P = port, under
# bash, output saved to evidence/<name>_<ip>_<port>_1.txt — the naming
# report.py reads automatically.
#
#   name     evidence name
#   src      service(s) from targets/ ("smb", "tcp-dns", ...)
#   tool     must be installed, or the check is skipped and listed
#   cmd      the command ($T, $P; must not use single quotes)
#   what     what it does, in one line
#   hit      regex: output that looks like a finding ("possible hit")
#   auto     True = a report rule recognises the result (finding becomes
#            Confirmed by itself); False = you judge it from SAFE-CHECKS.md
#   look     what to look for when you review it
#   needs    "root" | "domain" | "data" | "testssl" — only with that
#            condition / flag
# ---------------------------------------------------------------------------

CHECKS = [
    dict(name="dns-axfr", src="dns", tool="dig", needs="domain",
         what="DNS zone transfer for each --domain",
         cmd='for d in $DOMAINS; do echo "## $d"; dig axfr @$T -p $P $d '
             '+time=5 +tries=1; done',
         hit=r"XFR size: \d+ records", auto=False,
         look="`XFR size: N records` = the whole zone was handed out "
              "(`Transfer failed.` = refused)."),
    dict(name="tftp-get", src="tftp", tool="tftp",
         what="TFTP: try to download a few common config file names",
         cmd='cd "$(mktemp -d)" && for f in startup-config running-config '
             'config.txt boot.ini; do tftp $T $P -c get $f 2>/dev/null; '
             '[ -s $f ] && echo "GOT $f ($(wc -c < $f) bytes) in $PWD"; '
             'done; true',
         hit=r"^GOT ", auto=False,
         look="`GOT <file>` = downloaded without authentication — open the "
              "file (path in the line) for passwords / configs."),
    dict(name="finger-users", src="finger", tool="nc",
         what="Finger: ask about root and who is logged in",
         cmd='echo root | nc -w 5 $T $P; echo; echo | nc -w 5 $T $P',
         hit=r"Login|Name:|Directory:", auto=False,
         look="User names, home directories, login times = user "
              "enumeration."),
    dict(name="nfs-mount", src="rpcbind", tool="showmount", needs="root",
         what="NFS: mount every export read-only and list it",
         cmd='for e in $(showmount -e --no-headers $T 2>/dev/null | '
             'cut -d" " -f1); do d=$(mktemp -d); if mount -t nfs -o '
             'ro,nolock,soft,timeo=50 "$T:$e" "$d" </dev/null; then echo '
             '"## $T:$e"; ls -la "$d" | head -40; umount "$d"; fi; '
             'rmdir "$d"; done; true',
         hit=r"^## ", auto=False,
         look="A listing under `## <export>` = mountable by anyone. Sensitive "
              "files (home dirs, keys, backups) or `/` itself are the "
              "finding."),
    dict(name="smb-browse", src="smb", tool="smbclient",
         what="SMB: list every disk share anonymously, then `ls` in each",
         cmd='smbclient -N -L //$T -p $P -g 2>/dev/null | grep "^Disk|" | '
             'cut -d"|" -f2 | while read -r s; do echo "## $s"; smbclient -N '
             '"//$T/$s" -p $P -c "ls" </dev/null 2>&1 | head -40; done; true',
         hit=r"^\s+\S.*\s+[DAHNRS]+\s+\d+\s+\w{3} \w{3}", auto=False,
         look="File listings under `## <share>` = readable without "
              "credentials. Note what kind of data it is (don't copy it)."),
    dict(name="ldap-dump", src="ldap", tool="ldapsearch",
         what="LDAP: read up to 50 entries of each naming context anonymously",
         cmd='S=ldap; { [ $P = 636 ] || [ $P = 3269 ]; } && S=ldaps; for nc '
             'in $(ldapsearch -x -H $S://$T:$P -s base -b "" namingContexts '
             '2>/dev/null | sed -n "s/^namingContexts: //p"); do echo '
             '"## $nc"; ldapsearch -x -H $S://$T:$P -b "$nc" -z 50 2>&1 | '
             'head -200; done; true',
         hit=r"^dn: (?!$)", auto=False,
         look="`dn:` entries (users, groups, computers) = anonymous bind "
              "reads the directory."),
    dict(name="ike-main", src="ike", tool="ike-scan",
         what="IKE: main-mode handshake (transforms, vendor IDs)",
         cmd='ike-scan -M --sport=0 --dport=$P $T',
         hit=r"Main Mode Handshake returned", auto=False,
         look="The `SA=` line: DES / 3DES, MD5 / SHA1 or DH group 1/2 = "
              "weak VPN crypto."),
    dict(name="iscsi-disc", src="iscsi", tool="iscsiadm", needs="root",
         what="iSCSI: target discovery",
         cmd='iscsiadm -m discovery -t st -p $T:$P',
         hit=r",\d+ iqn\.", auto=False,
         look="`<ip>:<port>,1 iqn....` lines = targets listed without CHAP."),
    dict(name="cql-anon", src="cassandra", tool="cqlsh",
         what="Cassandra: anonymous login, list keyspaces",
         cmd='cqlsh $T $P --connect-timeout=10 -e "DESCRIBE KEYSPACES"',
         hit=r"system_auth|system_schema", auto=False,
         look="A keyspace list = anonymous access to the database."),
    dict(name="mongo-anon", src="mongodb", tool="mongosh",
         what="MongoDB: anonymous access, list databases",
         cmd='mongosh --host $T --port $P --quiet --eval '
             '"db.adminCommand({listDatabases:1}).databases.map(d => d.name)"',
         hit=r"'admin'|'local'|'config'", auto=False,
         look="A database list = no authentication."),
    dict(name="couch-peek", src="couchdb", tool="curl", needs="data",
         what="CouchDB: 5 documents from each database",
         cmd='U=http://$T:$P; curl -s -m 5 $U/ >/dev/null || U=https://$T:$P; '
             'for d in $(curl -sk -m 10 $U/_all_dbs | tr -d "[]\\"" | '
             'tr "," " " | head -c 2000); do echo "## $d"; curl -sk -m 10 '
             '"$U/$d/_all_docs?limit=5"; echo; done',
         hit=r'"rows":\[\{', auto=False,
         look="Documents readable without auth. Note database names and the "
              "kind of data only."),
    dict(name="es-peek", src="elasticsearch", tool="curl", needs="data",
         what="Elasticsearch: cluster info + 5 documents from each index",
         cmd='U=http://$T:$P; curl -s -m 5 $U/ >/dev/null || U=https://$T:$P; '
             'curl -sk -m 10 "$U/" | head -8; for i in $(curl -sk -m 10 '
             '"$U/_cat/indices?h=index" | head -20); do echo "## $i"; '
             'curl -sk -m 10 "$U/$i/_search?size=5"; echo; done',
         hit=r'"hits":\{"total"', auto=True,
         look="Index contents readable without auth. Note index names and "
              "the kind of data only."),
    dict(name="redis-config", src="redis", tool="redis-cli",
         what="Redis: server info, data directory, key counts",
         cmd='redis-cli -h $T -p $P info server | head -5; redis-cli -h $T '
             '-p $P config get dir; redis-cli -h $T -p $P info keyspace',
         hit=r"redis_version:", auto=True,
         look="`redis_version:` = no AUTH. `config get dir` shows where data "
              "lives; `db0:keys=` how much."),
    dict(name="mqtt-topics", src="mqtt", tool="mosquitto_sub",
         what="MQTT: read every topic for 10 seconds",
         cmd='mosquitto_sub -h $T -p $P -t "#" -v -W 10 2>&1 | head -50',
         hit=r"^(?!Error|Connection|Timed out)\S+ \S", auto=False,
         look="`<topic> <message>` lines = anyone can read the broker's "
              "traffic."),
    dict(name="docker-ps", src="docker", tool="curl",
         what="Docker API: version + container list",
         cmd='U=http://$T:$P; curl -s -m 5 $U/version >/dev/null || '
             'U=https://$T:$P; curl -sk -m 10 "$U/version"; echo; '
             'curl -sk -m 10 "$U/containers/json?all=1"',
         hit=r'"ApiVersion"', auto=True,
         look="`ApiVersion` = unauthenticated Docker API (root on the host). "
              "The container list shows what runs there."),
    dict(name="etcd-keys", src="etcd", tool="etcdctl",
         what="etcd: version + key names (no values)",
         cmd='curl -s -m 10 http://$T:$P/version; echo; ETCDCTL_API=3 '
             'etcdctl --endpoints=http://$T:$P --command-timeout=10s get / '
             '--prefix --keys-only | head -100',
         hit=r'"etcdserver"', auto=True,
         look="Key names readable = secrets store open (look for "
              "`/registry/secrets/...`)."),
    dict(name="k8s-anon", src="kubernetes", tool="curl",
         what="Kubernetes API: anonymous /apis and namespaces",
         cmd='curl -sk -m 10 https://$T:$P/apis | head -40; echo; '
             'curl -sk -m 10 https://$T:$P/api/v1/namespaces | head -40',
         hit=r'"kind":\s*"NamespaceList"', auto=False,
         look="A `NamespaceList` = anonymous users can read the cluster "
              "(anything beyond 401 / 403 is worth a look)."),
    dict(name="rsync-list", src="rsync", tool="rsync",
         what="rsync: list the files of every module",
         cmd='for m in $(rsync --list-only --timeout=20 rsync://$T:$P/ '
             '</dev/null | cut -f1 | tr -d " "); do echo "## $m"; rsync '
             '--list-only --timeout=20 "rsync://$T:$P/$m/" </dev/null 2>&1 | '
             'head -30; done; true',
         hit=r"^[d-][rwx-]{9}\s", auto=False,
         look="File lines under `## <module>` = readable without "
              "authentication."),
    dict(name="nntp-list", src="nntp", tool="nc",
         what="NNTP: list newsgroups",
         cmd='printf "LIST\\r\\nQUIT\\r\\n" | nc -w 5 $T $P | head -50',
         hit=r"^215", auto=False,
         look="`215` followed by group names = readable without auth."),
    dict(name="svn-log", src="svn", tool="svn",
         what="Subversion: last 20 commits",
         cmd='svn log --non-interactive -l 20 svn://$T:$P/',
         hit=r"^r\d+ \|", auto=False,
         look="Commit lines (`r123 | user | date`) = source history "
              "readable anonymously."),
    dict(name="rtsp-probe", src="rtsp", tool="ffprobe",
         what="RTSP: open the default stream (metadata only)",
         cmd='ffprobe -v error -rw_timeout 10000000 -rtsp_transport tcp '
             '-show_streams rtsp://$T:$P/ 2>&1 | head -30',
         hit=r"codec_type=video|\[STREAM\]", auto=False,
         look="`codec_type=video` = the camera stream opens without a "
              "password (watch it by hand with `ffplay`)."),
    dict(name="upnp-desc", src="upnp", tool="curl",
         what="UPnP: fetch the device description found by recon",
         cmd='for u in $(grep -ho "http://$T:[0-9]*/[^ ]*" '
             'service-checks/port-*-upnp.txt 2>/dev/null | sort -u); do echo '
             '"## $u"; curl -s -m 10 "$u" | head -60; done; true',
         hit=r"<modelName>|<deviceType>", auto=False,
         look="Model, firmware and service list — check the model against "
              "known UPnP / router CVEs."),
    dict(name="cups-admin", src="ipp", tool="curl",
         what="CUPS: is /admin reachable",
         cmd='curl -s -m 10 -o /dev/null -w "%{http_code} /admin\\n" '
             'http://$T:$P/admin',
         hit=r"^200 ", auto=False,
         look="`200 /admin` = printer administration open to the network."),
    dict(name="zk-info", src="zookeeper", tool="nc",
         what="Zookeeper: server stats and sessions",
         cmd='for c in srvr dump; do echo "## $c"; echo $c | nc -w 5 $T $P; '
             'done',
         hit=r"Zookeeper version", auto=False,
         look="`Zookeeper version` / session list = cluster info without "
              "auth."),
    dict(name="rdp-nla", src="rdp", tool="nxc",
         what="RDP: is Network Level Authentication required",
         cmd='nxc rdp $T --port $P',
         hit=r"nla:False", auto=False,
         look="`nla:False` = the login screen is reachable before "
              "authentication (finding: RDP without NLA)."),
    dict(name="x11-info", src="x11", tool="xdpyinfo",
         what="X11: display information",
         cmd='xdpyinfo -display $T:$((P - 6000)) 2>&1 | head -30',
         hit=r"name of display:", auto=True,
         look="`name of display:` = anyone can open the screen."),
    dict(name="web-exposed", src="web", tool="curl",
         what="Web: a few well-known exposed files, http and https",
         cmd='for s in http https; do for p in /.git/HEAD /.svn/entries /.env '
             '/.DS_Store /server-status /phpinfo.php /backup.zip '
             '/backup.tar.gz; do c=$(curl -sk -m 8 -o /dev/null -w '
             '"%{http_code}" "$s://$T:$P$p"); [ "$c" = 200 ] && echo "200 '
             '$s://$T:$P$p"; done; done; true',
         hit=r"^200 ", auto=False,
         look="Each `200 <url>` is a lead, not proof — open it: some sites "
              "answer 200 for everything. A real `.git/HEAD` starts with "
              "`ref:`."),
    dict(name="tls-old", src="ssl", tool="openssl",
         what="TLS: prove SSLv3 / TLS 1.0 / TLS 1.1 handshakes",
         cmd='for v in -ssl3 -tls1 -tls1_1; do echo "## $v"; echo | openssl '
             's_client -connect $T:$P $v 2>&1 | grep -E "^New,|alert|no '
             'protocols"; done',
         hit=r"^New, (SSLv3|TLSv1(\.1)?), Cipher is (?!\(NONE\))\S+",
         auto=True,
         look="`New, TLSv1, Cipher is <cipher>` (or SSLv3 / TLSv1.1) = old "
              "protocol accepted; `Cipher is (NONE)` = refused."),
    dict(name="testssl", src="ssl", tool="testssl.sh", needs="testssl",
         what="TLS: full testssl.sh audit", timeout=900,
         cmd='testssl.sh --quiet --color 0 --warnings off $T:$P',
         hit=r"VULNERABLE|NOT ok", auto=False,
         look="Lines marked `VULNERABLE` or `NOT ok`."),
]

TIMEOUT = {"nfs-mount": 180, "ldap-dump": 120, "smb-browse": 120,
           "rsync-list": 120, "es-peek": 120, "couch-peek": 120}

IP_RX = re.compile(r"^[0-9a-fA-F:.]+$")


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

def target_files(outdir, src):
    """targets/ files for a service: "smb" = tcp+udp, "tcp-dns" = one."""
    tdir = os.path.join(outdir, "targets")
    if re.match(r"^(tcp|udp)-", src):
        pats = [f"port-*-{src}.txt"]
    else:
        pats = [f"port-*-tcp-{src}.txt", f"port-*-udp-{src}.txt"]
    files = []
    for pat in pats:
        files += sorted(glob.glob(os.path.join(tdir, pat)))
    return files


def pairs_for(outdir, src):
    """Sorted unique (ip, port) for a service — a host found on TCP and UDP
    of the same port is checked once."""
    out = set()
    for f in target_files(outdir, src):
        port = int(os.path.basename(f).split("-")[1])
        with open(f) as fh:
            for line in fh:
                ip = line.strip()
                if ip and IP_RX.match(ip):
                    try:
                        ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    out.add((ip, port))
    return sorted(out, key=lambda hp: (tuple(int(x) if x.isdigit() else 0
                                             for x in re.split(r"[.:]", hp[0])),
                                       hp[1]))


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def run_one(outdir, chk, ip, port, env_prefix):
    """Run one check against one host:port; write its evidence file."""
    rel = f"evidence/{chk['name']}_{ip}_{port}_1.txt"
    script = f"T={ip}; P={port}; {env_prefix}{chk['cmd']}"
    timeout = chk.get("timeout") or TIMEOUT.get(chk["name"], 60)
    rc, out, err = rf.run(["bash", "-c", script], timeout=timeout)
    text = (out or "") + (err if err and err != "timeout" else "")
    if rc == 124 and err == "timeout":
        text += f"\n(stopped after {timeout}s)\n"
    with open(os.path.join(outdir, rel), "w") as f:
        f.write(f"$ T={ip} P={port}; {chk['cmd']}\n")
        f.write(text)
    hit = bool(chk.get("hit") and re.search(chk["hit"], text, re.M))
    return {"check": chk["name"], "ip": ip, "port": port, "file": rel,
            "hit": hit, "empty": not text.strip(),
            "timeout": rc == 124 and err == "timeout"}


def local_checks(outdir):
    """Checks that only read files already on disk — no target traffic."""
    done = []
    if rf.which("searchsploit"):
        lines = []
        for x in ("scan-tcp.xml", "scan-udp.xml"):
            p = os.path.join(outdir, x)
            if os.path.exists(p):
                _, out, err = rf.run(["searchsploit", "--nmap", p],
                                     timeout=300)
                lines.append(f"$ searchsploit --nmap {x}\n{out}{err}")
        if lines:
            with open(os.path.join(outdir, "evidence", "searchsploit.txt"),
                      "w") as f:
                f.write("\n".join(lines))
            done.append(("searchsploit", "evidence/searchsploit.txt",
                         "Public exploits matching the versions in the scan. "
                         "Each match is a lead — confirm the exact version "
                         "against the vendor advisory."))
    hits = []
    for p in sorted(glob.glob(os.path.join(outdir, "service-checks",
                                           "port-*-msrpc.txt"))):
        host = ""
        with open(p, errors="replace") as fh:
            for line in fh:
                m = re.match(r"^===== (\S+) =====", line)
                if m:
                    host = m.group(1)
                elif re.search(r"MS-RPRN|MS-EFSR|MS-DFSNM|MS-FSRVP", line):
                    hits.append(f"{host}: {line.strip()}")
    if glob.glob(os.path.join(outdir, "service-checks", "port-*-msrpc.txt")):
        with open(os.path.join(outdir, "evidence", "rpc-coercion.txt"),
                  "w") as f:
            f.write("\n".join(sorted(set(hits))) + "\n" if hits
                    else "(no coercion interfaces in the rpcdump output)\n")
        done.append(("rpc-coercion", "evidence/rpc-coercion.txt",
                     "Hosts exposing coercion RPC interfaces (MS-RPRN = "
                     "PrinterBug, MS-EFSR = PetitPotam, …) — an NTLM relay "
                     "finding. Don't trigger them." if hits else
                     "Nothing found."))
    return done


def make_plan(outdir, domains=(), with_data=False, testssl=False, only=()):
    """([(check, [(ip, port)])] to run, [(check, n hosts, why)] skipped)."""
    plan, skipped = [], []
    for c in CHECKS:
        if only and c["name"] not in only:
            continue
        need = c.get("needs")
        why = None
        if need == "root" and not rf.is_root():
            why = "needs root (mount / iscsiadm) — re-run with sudo"
        elif need == "domain" and not domains:
            why = "needs the domain — add --domain corp.example"
        elif need == "data" and not with_data:
            why = "reads real data — only with --with-data (if in scope)"
        elif need == "testssl" and not testssl:
            why = "slow — only with --testssl"
        pairs = pairs_for(outdir, c["src"])
        if not pairs:
            continue  # service not in this scan — nothing to say
        if why is None and not rf.which(c["tool"]):
            why = f"`{c['tool']}` not installed"
        if why:
            skipped.append((c, len(pairs), why))
        else:
            plan.append((c, pairs))
    return plan, skipped


def execute(outdir, plan, skipped, domains=(), threads=8):
    """Run the plan in parallel, then the on-disk checks; write
    SAFE-CHECKS.md. Returns (results, index path). Ctrl-C stops every
    running check, writes a partial index and re-raises."""
    os.makedirs(os.path.join(outdir, "evidence"), exist_ok=True)
    env_prefix = ""
    if domains:
        env_prefix = f"DOMAINS={shlex.quote(' '.join(domains))}; "
    results = []
    if plan:
        jobs = [(c, ip, port) for c, pairs in plan for ip, port in pairs]
        ex = ThreadPoolExecutor(max_workers=threads)
        futs = [ex.submit(run_one, outdir, c, ip, port, env_prefix)
                for c, ip, port in jobs]
        try:
            for i, fut in enumerate(as_completed(futs), 1):
                r = fut.result()
                results.append(r)
                tag = "HIT " if r["hit"] else ("time" if r["timeout"]
                                               else "done")
                rf.log(f"safe ({i}/{len(jobs)}) {tag} {r['check']} "
                       f"{r['ip']}:{r['port']}", "+" if r["hit"] else "*")
        except KeyboardInterrupt:
            for f in futs:
                f.cancel()
            rf.kill_running()
            ex.shutdown(wait=False)
            rf.log("interrupted — every running check was stopped", "!")
            write_index(outdir, plan, skipped, results, [], interrupted=True)
            raise
        ex.shutdown()
    local = local_checks(outdir)
    return results, write_index(outdir, plan, skipped, results, local)


def main():
    ap = argparse.ArgumentParser(
        description="Run the SAFE checks of MANDATORY_CHECKS.md Part 1 on "
                    "every target of a ReconFlow output folder.")
    ap.add_argument("outdir", help="the folder given to reconflow.py -o")
    ap.add_argument("--domain", action="append", default=[], metavar="NAME",
                    help="domain for the DNS zone-transfer check (repeat for "
                         "several); without it that check is skipped")
    ap.add_argument("--with-data", action="store_true",
                    help="also read sample documents from open CouchDB / "
                         "Elasticsearch (real data — only if in scope)")
    ap.add_argument("--testssl", action="store_true",
                    help="also run a full testssl.sh audit per TLS port (slow)")
    ap.add_argument("--only", default="", metavar="A,B",
                    help="run only these checks (names from SAFE-CHECKS.md)")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("-y", "--yes", action="store_true",
                    help="don't ask before starting")
    ap.add_argument("--list", action="store_true",
                    help="list the checks and exit")
    ap.add_argument("--dry", action="store_true",
                    help="show what would run (checks and host:ports), run "
                         "nothing")
    args = ap.parse_args()

    if args.list:
        for c in CHECKS:
            extra = f"  [{c['needs']}]" if c.get("needs") else ""
            print(f"{c['name']:<14} {c['src']:<13} {c['what']}{extra}")
        return
    outdir = args.outdir
    if not os.path.isdir(os.path.join(outdir, "targets")):
        ap.error(f"{outdir}: no targets/ folder — give the ReconFlow output "
                 "folder (the -o folder)")
    only = {x.strip() for x in args.only.split(",") if x.strip()}
    bad = only - {c["name"] for c in CHECKS}
    if bad:
        ap.error(f"unknown check(s): {', '.join(sorted(bad))} (see --list)")
    for d in args.domain:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", d):
            ap.error(f"--domain {d!r}: letters, digits, dots and dashes only")

    plan, skipped = make_plan(outdir, args.domain, args.with_data,
                              args.testssl, only)

    n_jobs = sum(len(p) for _, p in plan)
    print("\n  AUTHORIZED USE ONLY. Safe, read-only checks (MANDATORY_CHECKS "
          "Part 1)\n  against the targets of "
          f"{os.path.abspath(outdir)}:")
    for c, pairs in plan:
        print(f"   {c['name']:<14} {len(pairs):>3} host:port  {c['what']}")
    for c, n, why in skipped:
        print(f"   {c['name']:<14} skipped — {why}")
    if args.dry:
        for c, pairs in plan:
            print(f"\n  {c['name']}:  T=<ip> P=<port>; {c['cmd']}")
            print("   " + ", ".join(f"{ip}:{port}" for ip, port in pairs))
        print("\n  --dry: nothing was run.")
        return
    if not plan:
        print("\n  Nothing to run.")
    elif not (args.yes or rf.ask_yes(f"\n  Run {n_jobs} check(s)? [y/N] ")):
        rf.log("aborted — nothing was run", "!")
        return

    try:
        results, index = execute(outdir, plan, skipped, args.domain,
                                 args.threads)
    except KeyboardInterrupt:
        rf.give_to_sudo_user(outdir)
        sys.exit(130)

    # Fold the new evidence into the report (reads files only).
    sys.modules.setdefault("reconflow", rf)
    import report
    if os.path.exists(os.path.join(outdir, "results.json")):
        report.build(outdir)
    rf.give_to_sudo_user(outdir)
    hits = sum(r["hit"] for r in results)
    rf.log(f"done — {len(results)} check run(s), {hits} possible hit(s). "
           f"Review: {index}", "+")


# ---------------------------------------------------------------------------
# For report.py: safe-check results that may be an issue
# ---------------------------------------------------------------------------

def review_items(outdir, records):
    """Possible issues for FINDINGS.md: every evidence/<check>_<ip>_<port>_1.txt
    of a ✍️ check (one no report rule judges) whose output matches the
    check's hit pattern, for a host:port still in the scan — plus the two
    on-disk checks when they found something. Recomputed from the files on
    every rebuild, so a re-run (or an `each` run with the same name) counts.
    Returns [{check, what, look, target, file, repro}] — repro is the
    check's command for that one host, ready to paste (bash or zsh)."""
    scanned = {(r["ip"], r["port"]) for r in records}
    evdir = os.path.join(outdir, "evidence")
    items = []
    for c in CHECKS:
        if c["auto"] or not c.get("hit"):
            continue
        rx = re.compile(rf"^{re.escape(c['name'])}_(.+)_(\d+)_1\.txt$")
        for fn in sorted(os.listdir(evdir)) if os.path.isdir(evdir) else ():
            m = rx.match(fn)
            if not m or (m.group(1), int(m.group(2))) not in scanned:
                continue
            with open(os.path.join(evdir, fn), errors="replace") as fh:
                text = fh.read()
            body = text.split("\n", 1)[1] if "\n" in text else ""
            if re.search(c["hit"], body, re.M):
                items.append({"check": c["name"], "what": c["what"],
                              "look": c["look"],
                              "target": f"{m.group(1)}:{m.group(2)}",
                              "file": f"evidence/{fn}",
                              "repro": repro_cmd(c, m.group(1), m.group(2),
                                                 body)})
    p = os.path.join(evdir, "rpc-coercion.txt")
    if os.path.exists(p):
        with open(p, errors="replace") as fh:
            lines = [ln for ln in fh.read().splitlines()
                     if ln.strip() and not ln.startswith("(")]
        if lines:
            items.append({"check": "rpc-coercion",
                          "what": "Coercion RPC interfaces in the rpcdump "
                                  "output",
                          "look": "MS-RPRN (PrinterBug) / MS-EFSR "
                                  "(PetitPotam) = NTLM relay surface. "
                                  "Don't trigger them.",
                          "target": ", ".join(sorted({ln.split(":")[0]
                                                      for ln in lines})),
                          "file": "evidence/rpc-coercion.txt",
                          "repro": "awk '/^===== /{h=$2} "
                                   "/MS-RPRN|MS-EFSR|MS-DFSNM|MS-FSRVP/"
                                   "{print h\": \"$0}' "
                                   "service-checks/port-*-msrpc.txt"})
    p = os.path.join(evdir, "searchsploit.txt")
    if os.path.exists(p):
        with open(p, errors="replace") as fh:
            n = sum(1 for ln in fh if re.search(r"\s\|\s\S+/\S+", ln))
        if n:
            items.append({"check": "searchsploit",
                          "what": f"{n} public exploit(s) matching scanned "
                                  "versions",
                          "look": "Each match is a lead — confirm the exact "
                                  "version against the vendor advisory.",
                          "target": "see file",
                          "file": "evidence/searchsploit.txt",
                          "repro": "searchsploit --nmap scan-tcp.xml; "
                                   "searchsploit --nmap scan-udp.xml"})
    return items


def repro_cmd(c, ip, port, body=""):
    """The check's command for one host, ready to paste. Run with bash so
    it works the same from zsh; the commands never contain single quotes.
    Run it from the output folder (some checks read service-checks/)."""
    env = f"T={ip} P={port}"
    if "$DOMAINS" in c["cmd"]:
        doms = re.findall(r"(?m)^## ([A-Za-z0-9.-]+)\s*$", body)
        env += f" DOMAINS={shlex.quote(' '.join(doms) or 'corp.example')}"
    return f"{env} bash -c '{c['cmd']}'"


# ---------------------------------------------------------------------------
# SAFE-CHECKS.md
# ---------------------------------------------------------------------------

def write_index(outdir, plan, skipped, results, local, interrupted=False):
    by_check = defaultdict(list)
    for r in results:
        by_check[r["check"]].append(r)
    q = shlex.quote(os.path.abspath(outdir))
    here = os.path.dirname(os.path.abspath(__file__))
    L = ["<!-- Generated by safechecks.py — re-running it replaces this file. "
         "-->",
         f"# Safe checks — {os.path.basename(os.path.abspath(outdir))}", "",
         f"Run {_dt.datetime.now():%Y-%m-%d %H:%M} by `safechecks.py` — the "
         "safe, read-only checks of `docs/workflow/MANDATORY_CHECKS.md` "
         "Part 1, on every host:port in `targets/`."
         + (" **Interrupted — results are incomplete.**" if interrupted
            else ""), "",
         "## What to do now", "",
         "1. **✅ checks need nothing from you** — `report.py` reads their "
         "files and marks the finding **Confirmed** when the output shows "
         "it (already done at the end of this run).",
         "2. **✍️ checks: the files marked ⚠️ possible hit** below are also "
         "listed in `FINDINGS.md` → *Safe checks — possible issues*, each "
         "with a ready-to-run command — work from there. A real problem: add "
         "a block under *3. New findings* in `manual-checklist.md` with "
         "`Evidence:` pointing to the file, then rebuild:", "",
         "   ```bash",
         f"   python3 {shlex.quote(os.path.join(here, 'report.py'))} {q}",
         "   ```", "",
         "3. Files without a mark showed nothing interesting — a quick look "
         "is enough.",
         "4. **Skipped checks** are listed at the end with the reason — "
         "install the tool or add the flag and re-run.",
         "5. Then the dangerous checks (Part 2 of MANDATORY_CHECKS.md) — "
         "never run by this script.", "",
         "## Summary", "",
         "| Check | What it does | Ran on | ⚠️ Possible hits | Report reads it |",
         "|---|---|---|---|---|"]
    for c, pairs in plan:
        rs = by_check.get(c["name"], [])
        hits = sum(r["hit"] for r in rs)
        L.append(f"| [`{c['name']}`](#{c['name']}) | {c['what']} | "
                 f"{len(rs)} of {len(pairs)} host:port | "
                 f"{'**' + str(hits) + '**' if hits else '0'} | "
                 f"{'✅ by itself' if c['auto'] else '✍️ you review'} |")
    for name, rel, _ in local:
        L.append(f"| [`{name}`](#{name}) | reads files on disk (no traffic) | "
                 f"— | — | ✍️ you review |")
    L.append("")

    for c, pairs in plan:
        rs = sorted(by_check.get(c["name"], []),
                    key=lambda r: (not r["hit"], r["file"]))
        L += [f'<a id="{c["name"]}"></a>', f"### {c['name']} — {c['what']}",
              "", f"{'✅ **Report reads it by itself.**' if c['auto'] else '✍️ **You review it.**'} "
              f"Look for: {c['look']}", "",
              "```bash", f"T=<ip> P=<port>; {c['cmd']}", "```", ""]
        for r in rs:
            mark = ("⚠️ **possible hit**" if r["hit"] else
                    "timed out" if r["timeout"] else
                    "no output" if r["empty"] else "")
            L.append(f"- [`{r['file']}`]({r['file']}) — {r['ip']}:{r['port']}"
                     + (f" — {mark}" if mark else ""))
        L.append("")

    for name, rel, note in local:
        L += [f'<a id="{name}"></a>', f"### {name}", "",
              f"✍️ [`{rel}`]({rel}) — {note}", ""]

    if skipped:
        L += ["## Skipped", "",
              "| Check | Hosts waiting | Why |", "|---|---|---|"]
        for c, n, why in skipped:
            L.append(f"| `{c['name']}` — {c['what']} | {n} | {why} |")
        L.append("")

    L += ["## Not done by this script", "",
          "What each check does: `docs/reference/SAFE_CHECKS.md`. Still in "
          "`docs/workflow/MANDATORY_CHECKS.md`:", "",
          "- **Judgement:** browsing each web app (`web-report.html`), "
          "looking at RDP login screens and camera streams.",
          "- **Part 2 — dangerous checks:** risky checks, credential "
          "testing, exploit confirmations, intrusive steps. Never run here.",
          ""]
    path = os.path.join(outdir, "SAFE-CHECKS.md")
    with open(path, "w") as f:
        f.write("\n".join(L))
    return path


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        rf.kill_running()
        print()
        rf.log("interrupted", "!")
        sys.exit(130)
