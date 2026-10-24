#!/usr/bin/env python3
"""
ReconFlow (reconflow.py) — Authorized network recon orchestrator (Metasploit DB-driven).

Workflow (fully automatic; anything it cannot do is handed back to you):
  1. Read targets from scope/inscope_ips.txt (CIDRs, /24s, ranges, single
     IPs — one per line) minus everything in scope/outofscope_ips.txt, which
     nmap never touches (--excludefile) and every later step filters out
     again. Everything is written to the output folder given with -o.
  2. nmap TCP (-sS) + optional UDP (-sU) with service/version/default-script/OS
     detection, saving ALL formats (-oA → .nmap/.xml/.gnmap). A full TCP
     scan runs in two phases: a fast all-ports sweep, then detection on the
     open ports only.
  3. Parse the XML, build a host->port->service model.
  4. Fan out per-service "<service>-open.txt" files (ftp, telnet, smb, rdp, ...).
  5. For every web-ish port, probe BOTH http:// and https:// and screenshot each
     into an HTML gallery report (gowitness, httpx fallback).
  6. PER-PORT PLAYBOOK: for every open port, run the matching safe enumeration
     commands (nmap NSE on the real port, smbclient, snmpwalk, ...) in
     parallel, saving output + a re-runnable commands.sh.
  7. Generate a Metasploit resource file (metasploit.rc) that creates a
     fresh workspace for this run, db_import's the scan XML, and runs the
     matching auxiliary modules PORT BY PORT with RHOSTS pulled from the DB
     (`services -p N -R`). Runs it if you say so at the start (or --msf) and
     msfconsole + the msf DB are available.
  8. SAFE MANUAL CHECKS (safechecks.py): the read-only checks of
     docs/workflow/MANDATORY_CHECKS.md Part 1 (share / directory listings,
     anonymous database access, exposed web files, ...) on every target;
     output to evidence/.
  9. Build the report (report.py): highlights (anonymous FTP, null sessions,
     VULNERABLE, ...) into FINDINGS.md (severity, every affected IP,
     reproduce steps, fix), safe-check results that may be an issue, and a
     'Manual follow-up' section for everything that needs a human: missing
     tools, timeouts, failed steps, services with no automation.

USE ONLY ON SYSTEMS YOU ARE AUTHORIZED TO TEST.

Requires: nmap. For the msf step: metasploit-framework + a running msf database
(postgresql; `msfdb init`). Everything else is optional and auto-detected —
a missing tool is skipped and listed under 'Manual follow-up' in FINDINGS.md.
"""

import argparse
import datetime as _dt
import html
import ipaddress
import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Service classification.
# ---------------------------------------------------------------------------

WEB_PORTS = {80, 81, 443, 591, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 4443,
             5000, 5443, 7001, 7443, 8000, 8008, 8080, 8081, 8088, 8090,
             8180, 8443, 8444, 8800, 8888, 9000, 9080, 9090, 9443, 10000, 16080}

WEB_NAMES = {"http", "https", "http-alt", "http-proxy", "https-alt", "ssl",
             "www", "http-mgmt", "websm"}

SSL_NAMES = {"https", "https-alt", "ldaps", "imaps", "pop3s", "smtps", "ftps",
             "wsmans", "globalcatldapssl"}
SSL_PORTS = {443, 465, 636, 990, 993, 995, 3269, 4443, 5443, 5986, 7443, 8443,
             9443}

# Services that negotiate TLS via STARTTLS -> sslscan flag (nmap handles it
# automatically). These get TLS checks even though the port isn't TLS-only.
STARTTLS = {"smtp": "--starttls-smtp", "submission": "--starttls-smtp",
            "ftp": "--starttls-ftp", "imap": "--starttls-imap",
            "pop3": "--starttls-pop3", "ldap": "--starttls-ldap",
            "postgresql": "--starttls-psql", "mysql": "--starttls-mysql",
            "xmpp-client": "--starttls-xmpp"}

PORT_BUCKET = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "smb", 143: "imap",
    161: "snmp", 389: "ldap", 445: "smb", 465: "smtp", 512: "rexec",
    513: "rlogin", 514: "rsh", 587: "smtp", 623: "ipmi", 636: "ldap",
    873: "rsync", 993: "imap", 995: "pop3", 1099: "rmi", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 3128: "proxy", 3268: "ldap",
    3269: "ldap", 3306: "mysql", 3389: "rdp", 5060: "sip", 5432: "postgres",
    1524: "bindshell", 3632: "distcc", 5900: "vnc", 5985: "winrm",
    5986: "winrm", 6000: "x11", 6379: "redis", 6667: "irc", 8009: "ajp",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
    69: "tftp", 79: "finger", 88: "kerberos", 119: "nntp", 123: "ntp",
    137: "netbios-ns", 500: "ike", 554: "rtsp", 631: "ipp", 902: "vmware",
    1883: "mqtt", 1900: "upnp", 2181: "zookeeper", 2379: "etcd",
    3260: "iscsi", 3690: "svn", 5353: "mdns", 5672: "amqp", 5984: "couchdb",
    6443: "kubernetes", 9042: "cassandra", 9100: "jetdirect",
    9160: "cassandra", 9418: "git", 10250: "kubelet",
}

# Exact nmap service names -> bucket. Exact (not substring) so that e.g.
# "tftp" doesn't land in "ftp".
NAME_BUCKET = {
    "ftp": "ftp", "ftps": "ftp", "ssh": "ssh", "telnet": "telnet",
    "smtp": "smtp", "smtps": "smtp", "submission": "smtp", "domain": "dns",
    "pop3": "pop3", "pop3s": "pop3", "imap": "imap", "imaps": "imap",
    "rpcbind": "rpcbind", "msrpc": "msrpc", "netbios-ssn": "smb",
    "microsoft-ds": "smb", "snmp": "snmp", "ldap": "ldap", "ldaps": "ldap",
    "globalcatldap": "ldap", "globalcatldapssl": "ldap", "exec": "rexec",
    "login": "rlogin", "shell": "rsh", "asf-rmcp": "ipmi", "ipmi": "ipmi",
    "rsync": "rsync", "java-rmi": "rmi", "rmiregistry": "rmi",
    "ms-sql-s": "mssql", "ms-sql-m": "mssql", "oracle-tns": "oracle",
    "oracle": "oracle", "nfs": "nfs", "mountd": "nfs", "nfs_acl": "nfs",
    "docker": "docker", "squid-http": "proxy", "mysql": "mysql",
    "ms-wbt-server": "rdp", "sip": "sip", "postgresql": "postgres",
    "vnc": "vnc", "wsman": "winrm", "wsmans": "winrm", "redis": "redis",
    "elasticsearch": "elasticsearch", "memcached": "memcached",
    "mongodb": "mongodb", "mongod": "mongodb", "x11": "x11", "irc": "irc",
    "ajp13": "ajp", "bindshell": "bindshell", "distccd": "distcc",
    "drb": "drb", "tftp": "tftp", "finger": "finger",
    "kerberos-sec": "kerberos", "kerberos": "kerberos", "kpasswd5": "kerberos",
    "nntp": "nntp", "ntp": "ntp", "netbios-ns": "netbios-ns", "isakmp": "ike",
    "rtsp": "rtsp", "ipp": "ipp", "vmware-auth": "vmware", "mqtt": "mqtt",
    "upnp": "upnp", "zookeeper": "zookeeper", "etcd-client": "etcd",
    "iscsi": "iscsi", "svn": "svn", "mdns": "mdns", "amqp": "amqp",
    "couchdb": "couchdb", "cassandra": "cassandra", "jetdirect": "jetdirect",
    "git": "git", "jdwp": "jdwp",
    # RPC programs on dynamic ports (enumerated via rpcbind on 111)
    "nlockmgr": "rpc", "status": "rpc", "rquotad": "rpc", "rstatd": "rpc",
    "rusersd": "rpc", "walld": "rpc", "ypbind": "rpc", "ypserv": "rpc",
}


def which(tool):
    return shutil.which(tool) is not None


def log(msg, level="*"):
    colors = {"*": "\033[94m", "+": "\033[92m", "!": "\033[91m", "-": "\033[93m"}
    c = colors.get(level, "")
    print(f"{c}[{level}]\033[0m {msg}", flush=True)


# Every child process still running, so Ctrl-C can stop all target
# traffic at once (kill_running).
_RUNNING = set()
_RUNNING_LOCK = threading.Lock()


def run(cmd, timeout=300, capture=True):
    """Run a command, return (rc, stdout, stderr). Never raises on nonzero.

    On timeout returns rc 124 with whatever output was captured so far.
    """
    pipe = subprocess.PIPE if capture else None
    # Captured commands never get the keyboard, so no tool can sit waiting
    # for input (the nmap scans keep it: a key press shows their progress).
    stdin = subprocess.DEVNULL if capture else None
    try:
        p = subprocess.Popen(cmd, stdin=stdin, stdout=pipe, stderr=pipe,
                             text=True, errors="replace")
    except FileNotFoundError:
        return 127, "", "not found"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)
    with _RUNNING_LOCK:
        _RUNNING.add(p)
    try:
        try:
            out, err = p.communicate(timeout=timeout)
            return p.returncode, (out or ""), (err or "")
        except subprocess.TimeoutExpired:
            p.kill()
            out, _ = p.communicate()
            return 124, (out or ""), "timeout"
    finally:
        with _RUNNING_LOCK:
            _RUNNING.discard(p)


def kill_running():
    """Kill every child process run() started that is still alive."""
    with _RUNNING_LOCK:
        procs = list(_RUNNING)
    for p in procs:
        try:
            p.kill()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Scope: in-scope targets minus out-of-scope exclusions.
# ---------------------------------------------------------------------------

SCOPE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scope")

# Written on first run (the scope files are git-ignored, so a fresh clone
# has none).
SCOPE_TEMPLATES = {
    "inscope_ips.txt": """\
# =============================================================================
# ReconFlow — IN-SCOPE targets (what you are allowed to test)
# =============================================================================
# One target per line; blank lines and #comments are ignored.
# Single IPs, CIDRs, ranges (10.0.0.1-50, 10.0.1-3.*) and hostnames all work.
# Hosts listed in outofscope_ips.txt are removed from this list.
# Syntax and a worked example: scope/ips.example.md
# =============================================================================

""",
    "outofscope_ips.txt": """\
# =============================================================================
# ReconFlow — OUT-OF-SCOPE targets (never scanned, checked or touched)
# =============================================================================
# One target per line; blank lines and #comments are ignored.
# Use it to carve hosts out of a big in-scope subnet.
#
# USE IP ADDRESSES HERE, NOT HOSTNAMES. nmap excludes only the first address a
# hostname resolves to, and ReconFlow can only re-check a hostname if reverse
# DNS returns the same name. An IP can't be missed. (README.md -> Scope files.)
#
# Examples:
#   10.0.0.1              # gateway
#   10.0.0.200-220        # client's production DB cluster
#   10.0.5.0/28
# Syntax and a worked example: scope/ips.example.md
# =============================================================================

""",
}


# The output folder once it exists — handed to the sudo user on exit.
_OUTDIR = None


def give_to_sudo_user(path):
    """Under sudo, hand path (recursively) to the real user, so they can
    edit it, tee into evidence/ and spool msf-manual.log without root."""
    if not (is_root() and "SUDO_UID" in os.environ):
        return
    uid = int(os.environ["SUDO_UID"])
    gid = int(os.environ.get("SUDO_GID", uid))
    os.chown(path, uid, gid)
    for root, dirs, files in os.walk(path):
        for n in dirs + files:
            os.chown(os.path.join(root, n), uid, gid, follow_symlinks=False)


def ensure_scope_file(name):
    """Create scope/<name> from its template if missing. Returns its path."""
    path = os.path.join(SCOPE_DIR, name)
    if not os.path.exists(path):
        os.makedirs(SCOPE_DIR, exist_ok=True)
        with open(path, "w") as f:
            f.write(SCOPE_TEMPLATES[name])
        # Under sudo, hand the file to the real user so they can edit it.
        give_to_sudo_user(path)
        what = ("add your targets there" if name == "inscope_ips.txt"
                else "add exclusions there (optional)")
        log(f"created {_rel(path)} — {what}", "+")
    return _rel(path)


def _rel(path):
    """Path relative to the cwd when that's shorter, for display."""
    rel = os.path.relpath(path)
    return rel if not rel.startswith("..") else path


def read_target_list(path):
    """Entries from a target file: whitespace-separated, `#` comments."""
    out = []
    with open(path) as f:
        for ln in f:
            out += ln.split("#", 1)[0].split()
    return out


def _octet_range(spec):
    """nmap octet syntax ('5', '1-50', '1,3,7-9', '*', '10-') -> set of ints."""
    vals = set()
    for part in spec.split(","):
        if part == "*":
            part = "0-255"
        lo, sep, hi = part.partition("-")
        lo = int(lo) if lo else 0
        hi = int(hi) if hi else (255 if sep else lo)
        vals.update(range(lo, hi + 1))
    return vals


def is_hostname(entry):
    """True unless the entry is an IP, CIDR or nmap octet range."""
    try:
        ipaddress.ip_network(entry, strict=False)
        return False
    except ValueError:
        parts = entry.split(".")
        return not (len(parts) == 4 and
                    all(re.fullmatch(r"[\d,*-]+", p) for p in parts))


def scope_matcher(entries):
    """match(ip, hostname='') -> True if any entry covers the host. Entries:
    single IPs, CIDRs, nmap octet ranges (10.0.0.1-50, 10.0.1-3.*), hostnames."""
    nets, octs, names = [], [], set()
    for e in entries:
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
            continue
        except ValueError:
            pass
        parts = e.split(".")
        if len(parts) == 4 and all(re.fullmatch(r"[\d,*-]+", p) for p in parts):
            octs.append([_octet_range(p) for p in parts])
        else:
            names.add(e.lower())

    def match(ip, hostname=""):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if any(a.version == n.version and a in n for n in nets):
            return True
        if a.version == 4:
            o = [int(x) for x in ip.split(".")]
            if any(all(o[i] in r[i] for i in range(4)) for r in octs):
                return True
        return bool(hostname) and hostname.lower() in names
    return match


# ---------------------------------------------------------------------------
# Scanning — saves ALL formats via -oA.
# ---------------------------------------------------------------------------

def is_root():
    return not hasattr(os, "geteuid") or os.geteuid() == 0


# nmap's default scripts (-sC) minus the ones that act on the target.
# http-open-proxy is in the "default" category but makes the target fetch an
# outside site — a risky check (PLAYBOOK "proxy"), so it never runs here.
SCAN_SCRIPTS = "default and not http-open-proxy"


def open_tcp_ports(xml_path):
    """(set of open TCP ports, [ips with an open port]) from an nmap XML."""
    ports, ips = set(), []
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError) as e:
        log(f"Could not parse {xml_path}: {e}", "!")
        return ports, ips
    for host in root.findall("host"):
        addr = next((a.get("addr") for a in host.findall("address")
                     if a.get("addrtype") in ("ipv4", "ipv6")), None)
        found = {int(p.get("portid")) for p in host.findall("ports/port")
                 if p.get("protocol") == "tcp"
                 and p.find("state") is not None
                 and p.find("state").get("state") == "open"}
        if addr and found:
            ips.append(addr)
            ports |= found
    return ports, ips


def hosts_down(xml_path):
    """How many targets nmap reported down (no reply to host discovery)."""
    try:
        h = ET.parse(xml_path).getroot().find("runstats/hosts")
        return int(h.get("down", 0)) if h is not None else 0
    except (ET.ParseError, OSError, ValueError):
        return 0


def nmap_scan(targets_file, outdir, do_udp, top_udp, extra, timing, manual,
              full=False, exclude_file=None, no_ping=False):
    """Run TCP (and optionally UDP) nmap scans from an -iL file, skipping
    everything in exclude_file (--excludefile).

    A full scan runs in two phases: a fast all-ports sweep (scan-tcp-ports.*),
    then version/script/OS detection only on the ports found open
    (scan-tcp.*). Saves all three formats (.nmap/.xml/.gnmap) per scan.
    Returns (scan XMLs, sweep XMLs): the first feed the report and
    Metasploit; the second only host info.
    Without root, falls back to a connect scan (-sT, no -O, no UDP) and lists
    what was dropped under 'Manual follow-up'.
    """
    xmls, aux = [], []
    root = is_root()
    excl = ["--excludefile", exclude_file] if exclude_file else []
    pn = ["-Pn"] if no_ping else []
    rerun = f"`sudo python3 {' '.join(shlex.quote(a) for a in sys.argv)}`"
    if not root:
        log("not root: using connect scan (-sT), skipping OS detection"
            + (" and UDP" if do_udp else ""), "-")
        manual["auto"].append((
            "Scan ran without root — OS detection" + (" and UDP scan" if do_udp
                                                      else "") + " skipped",
            [f"Re-run as root for SYN scan + OS fingerprint: {rerun}"]))

    tcp_prefix = os.path.join(outdir, "scan-tcp")
    extra_args = shlex.split(extra) if extra else []
    # -p<spec> / --top-ports / --port-ratio in --extra override the default
    # port selection (all TCP ports / --top-udp), so nmap never gets two
    # port specs.
    user_ports = any(a.startswith("-p") or a in ("--top-ports", "--port-ratio")
                     for a in extra_args)
    if user_ports:
        log("--extra sets the ports — using them instead of the defaults", "-")
    elif not full:
        manual["auto"].append((
            "Only the top 1000 TCP ports were scanned (--quick)",
            ["Services on high ports (e.g. distcc 3632, 8787) can be missed — "
             "re-run without `--quick` for all 65535."]))
    if not do_udp:
        manual["auto"].append((
            "UDP was not scanned (--no-udp)",
            ["SNMP, DNS, TFTP, NTP, IPMI, NetBIOS … can be missed — re-run "
             "without `--no-udp`."]))
    stype = ["-sS"] if root else ["-sT"]
    detect = (["-O"] if root else []) + ["-sV", "--script", SCAN_SCRIPTS]
    tcp_xml = tcp_prefix + ".xml"
    first_xml = tcp_xml  # the scan whose host discovery counts "down"
    if full and not user_ports:
        # Phase 1: which ports are open (fast, no detection).
        sweep_prefix = os.path.join(outdir, "scan-tcp-ports")
        sweep_cmd = ["nmap", "-iL", targets_file] + excl + pn + [
            "-p-"] + stype + ["--open", f"-{timing}", "-oA",
                              sweep_prefix] + extra_args
        log(f"TCP port sweep (phase 1/2): {shlex.join(sweep_cmd)}")
        rc, _, err = run(sweep_cmd, timeout=86400, capture=False)
        sweep_xml = first_xml = sweep_prefix + ".xml"
        ports, live = set(), []
        if os.path.exists(sweep_xml):
            aux.append(sweep_xml)
            ports, live = open_tcp_ports(sweep_xml)
        else:
            log(f"TCP port sweep produced no XML (rc={rc}): {err}", "!")
        # Phase 2: detection on the open ports of the hosts that have them.
        if ports:
            live_file = os.path.join(outdir, "scan-tcp-hosts.txt")
            with open(live_file, "w") as f:
                f.write("\n".join(live) + "\n")
            tcp_cmd = ["nmap", "-iL", live_file] + excl + [
                "-Pn", "-p", ",".join(str(p) for p in sorted(ports))] + (
                stype + detect + ["--open", f"-{timing}", "-oA",
                                  tcp_prefix] + extra_args)
            log(f"TCP detection (phase 2/2, {len(ports)} port(s) on "
                f"{len(live)} host(s)): {shlex.join(tcp_cmd)}")
            rc, _, err = run(tcp_cmd, timeout=86400, capture=False)
            if os.path.exists(tcp_xml):
                xmls.append(tcp_xml)
            else:
                log(f"TCP scan produced no XML (rc={rc}): {err}", "!")
        elif os.path.exists(sweep_xml):
            log("port sweep found no open TCP ports — skipping detection", "-")
    else:
        tcp_cmd = ["nmap", "-iL", targets_file] + excl + pn + stype + (
            detect + ["--open", f"-{timing}", "-oA", tcp_prefix]
            + extra_args)
        log(f"TCP scan: {shlex.join(tcp_cmd)}")
        rc, _, err = run(tcp_cmd, timeout=86400, capture=False)
        if os.path.exists(tcp_xml):
            xmls.append(tcp_xml)
        else:
            log(f"TCP scan produced no XML (rc={rc}): {err}", "!")
    down = 0 if no_ping else hosts_down(first_xml)
    if down:
        manual["auto"].append((
            f"{down} in-scope address(es) did not answer host discovery — "
            "not scanned",
            ["Usually just unused addresses, but hosts that block ping look "
             "the same.",
             "If live hosts may be among them, re-run with `--pn` (treats "
             "every address as up — slower on sparse ranges)."]))

    if do_udp and root:
        udp_prefix = os.path.join(outdir, "scan-udp")
        # --extra applies here too; its port spec (e.g. -p T:80,U:53) wins
        # over --top-udp.
        udp_ports = [] if user_ports else ["--top-ports", str(top_udp)]
        udp_cmd = ["nmap", "-iL", targets_file] + excl + pn + [
            "-sU", "-sV", "--open"] + udp_ports + [
            f"-{timing}", "-oA", udp_prefix] + extra_args
        log(f"UDP scan: {shlex.join(udp_cmd)}")
        rc, _, err = run(udp_cmd, timeout=86400, capture=False)
        udp_xml = udp_prefix + ".xml"
        if os.path.exists(udp_xml):
            xmls.append(udp_xml)
        else:
            log(f"UDP scan produced no XML (rc={rc}): {err}", "-")
    return xmls, aux


def parse_nmap(xml_paths):
    """Parse nmap XML files into a list of dicts per open port."""
    records = []
    for path in xml_paths:
        try:
            tree = ET.parse(path)
        except (ET.ParseError, OSError) as e:
            log(f"Could not parse {path}: {e}", "!")
            continue
        # Did this scan run nmap's default scripts? Then ssl-cert ran on
        # every TLS / STARTTLS port, so its absence means no TLS there.
        scripted = bool(re.search(r"(^|\s)(-sC|-A)\b|--script[ =]\"?default",
                                  tree.getroot().get("args", "")))
        for host in tree.getroot().findall("host"):
            st = host.find("status")
            if st is not None and st.get("state") != "up":
                continue
            addr = None
            for a in host.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    addr = a.get("addr")
                    break
            if not addr:
                continue
            hostname = ""
            hn = host.find("hostnames/hostname")
            if hn is not None:
                hostname = hn.get("name", "")
            ports = host.find("ports")
            if ports is None:
                continue
            for p in ports.findall("port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = int(p.get("portid"))
                proto = p.get("protocol")
                svc = p.find("service")
                name = svc.get("name", "") if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                extrainfo = svc.get("extrainfo", "") if svc is not None else ""
                tunnel = svc.get("tunnel", "") if svc is not None else ""
                ostype = svc.get("ostype", "") if svc is not None else ""
                scripts = {s.get("id", "") for s in p.findall("script")}
                records.append({
                    "ip": addr, "hostname": hostname, "port": portid,
                    "proto": proto, "name": name, "product": product,
                    "version": version, "extrainfo": extrainfo,
                    "tunnel": tunnel, "ostype": ostype,
                    # True/False when the scan can tell; None = unknown.
                    "tls": ("ssl-cert" in scripts) if scripted else None,
                })
    return records


def host_info(xml_paths):
    """ip -> {hostname, os} for every host nmap saw up, plus the scan
    command lines (from <nmaprun args=...>)."""
    hosts, cmds = {}, []
    for path in xml_paths:
        try:
            root = ET.parse(path).getroot()
        except (ET.ParseError, OSError):
            continue
        if root.get("args"):
            cmds.append(root.get("args"))
        for host in root.findall("host"):
            st = host.find("status")
            if st is None or st.get("state") != "up":
                continue
            addr = None
            for a in host.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    addr = a.get("addr")
                    break
            if not addr:
                continue
            h = hosts.setdefault(addr, {"hostname": "", "os": ""})
            hn = host.find("hostnames/hostname")
            if hn is not None and not h["hostname"]:
                h["hostname"] = hn.get("name", "")
            om = host.find("os/osmatch")
            if om is not None and not h["os"]:
                h["os"] = f"{om.get('name')} ({om.get('accuracy')}%)"
    return hosts, cmds


def svc_name(rec):
    return (rec["name"] or "").lower().split("?")[0]


def is_web(rec):
    name = svc_name(rec)
    if name.startswith("http") or name in WEB_NAMES:
        return True
    # Unidentified service on a web port, or behind TLS: worth a probe.
    return name in ("", "unknown") and (rec["port"] in WEB_PORTS
                                        or rec["tunnel"] == "ssl")


def is_ssl(rec):
    return (rec["tunnel"] == "ssl" or svc_name(rec) in SSL_NAMES
            or rec["port"] in SSL_PORTS)


def bucket_for(rec):
    name = svc_name(rec)
    if name in NAME_BUCKET:
        return NAME_BUCKET[name]
    if rec["port"] in PORT_BUCKET:
        return PORT_BUCKET[rec["port"]]
    if is_web(rec):
        return "web"
    return name.replace("/", "-") or f"port-{rec['port']}"


def profiles_for(rec):
    """Playbook profiles that apply: the bucket, plus 'web' for web-ish
    services in another bucket (e.g. WinRM or Elasticsearch over HTTP)."""
    b = bucket_for(rec)
    profs = [b]
    if b != "web" and is_web(rec) and rec["proto"] == "tcp":
        profs.append("web")
    if rec["proto"] == "tcp" and (is_ssl(rec) or starttls_ok(rec)):
        profs.append("ssl")
    return profs


def starttls_ok(rec):
    """A STARTTLS-capable service that offers TLS — or may: only skipped
    when the scan's ssl-cert script saw no certificate (rec['tls'] False)."""
    return svc_name(rec) in STARTTLS and rec.get("tls") is not False


def no_starttls(records):
    """STARTTLS-capable services where the scan saw no TLS (no TLS checks)."""
    return [r for r in records if r["proto"] == "tcp" and not is_ssl(r)
            and svc_name(r) in STARTTLS and r.get("tls") is False]


# ---------------------------------------------------------------------------
# Per-port playbook.
#
#   checks : (tool, command template) — safe enumeration, run automatically.
#            Placeholders: {ip} {port} {sU} (-sU for UDP) {scheme} {ldap}.
#            {scheme} expands to BOTH http and https for the web profile.
#   msf    : auxiliary modules run from metasploit.rc against the DB.
#   login  : credential module — emitted COMMENTED OUT, operator opts in.
#   manual : steps a human must do (TARGET/PORT placeholders; shown as hints
#            for services with no automation).
#   risky  : (tool, command template) — checks that act on the target (login
#            attempts, relay tests, …). NEVER run; listed per host in
#            manual-checklist.md, FINDINGS.md and commands.sh for the tester
#            to run deliberately.
#   risky_finding : the finding id the risky commands test for. A risky
#            entry may carry its own id as a third element instead.
# ---------------------------------------------------------------------------

USER_FILE = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
PASS_FILE = ("/usr/share/seclists/Passwords/Common-Credentials/"
             "xato-net-10-million-passwords-1000.txt")

PLAYBOOK = {
    "ftp": {
        "checks": [("nmap", "nmap -Pn -p{port} --script "
                            "ftp-anon,ftp-syst,ftp-bounce {ip}")],
        "msf": ["auxiliary/scanner/ftp/ftp_version",
                "auxiliary/scanner/ftp/ftp_anonymous"],
        "login": "auxiliary/scanner/ftp/ftp_login",
        "manual": [
            "`ftp -P PORT TARGET` → try anonymous/anonymous; if in, `ls -la` "
            "and `put` a test file to check write access.",
            "Map the banner/daemon version to known CVEs (e.g. vsftpd 2.3.4).",
        ],
    },
    "ssh": {
        "checks": [("nmap", "nmap -Pn -p{port} --script "
                            "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods {ip}"),
                   ("ssh-audit", "ssh-audit -p {port} {ip}")],
        "msf": ["auxiliary/scanner/ssh/ssh_version"],
        "login": "auxiliary/scanner/ssh/ssh_login",
        "manual": [
            "`ssh -v -p PORT user@TARGET` → note allowed auth "
            "(publickey vs password).",
            "Weak algorithms/keys from ssh-audit / ssh2-enum-algos → finding.",
        ],
    },
    "telnet": {
        "checks": [("nmap", "nmap -Pn -p{port} --script "
                            "telnet-encryption,telnet-ntlm-info {ip}")],
        "msf": ["auxiliary/scanner/telnet/telnet_version"],
        "login": "auxiliary/scanner/telnet/telnet_login",
        "manual": [
            "`telnet TARGET PORT` → read banner; cleartext remote login is a "
            "finding on its own.",
            "Try vendor default creds for the fingerprinted device.",
        ],
    },
    "smtp": {
        "checks": [("nmap", "nmap -Pn -p{port} --script "
                            "smtp-commands,smtp-ntlm-info {ip}")],
        # smtp-enum-users guesses usernames (RCPT/VRFY against a wordlist).
        "risky": [("nmap", "nmap -Pn -p{port} --script smtp-open-relay {ip}"),
                  ("nmap", "nmap -Pn -p{port} --script smtp-enum-users {ip}",
                   "smtp-user-enum")],
        "risky_finding": "smtp-open-relay",
        "msf": ["auxiliary/scanner/smtp/smtp_version"],
        "manual": [
            "`nc TARGET PORT` → `EHLO x`, `VRFY root`, `EXPN` to confirm "
            "user enumeration.",
            "Confirm any open relay by sending external→external test mail.",
        ],
    },
    "dns": {
        "checks": [("nmap", "nmap -Pn {sU} -p{port} --script "
                            "dns-nsid,dns-recursion {ip}"),
                   ("dig", "dig @{ip} -p {port} version.bind chaos txt "
                           "+time=5 +tries=1")],
        "manual": [
            "Zone transfer needs the domain: "
            "`dig axfr @TARGET -p PORT <domain>` — success = full record dump.",
            "Open recursion for external clients → finding.",
        ],
    },
    "pop3": {
        "checks": [("nmap", "nmap -Pn -p{port} --script "
                            "pop3-capabilities,pop3-ntlm-info {ip}")],
        "msf": ["auxiliary/scanner/pop3/pop3_version"],
        "manual": ["Cleartext USER/PASS without STARTTLS → finding."],
    },
    "imap": {
        "checks": [("nmap", "nmap -Pn -p{port} --script "
                            "imap-capabilities,imap-ntlm-info {ip}")],
        "msf": ["auxiliary/scanner/imap/imap_version"],
        "manual": ["Cleartext LOGIN without STARTTLS → finding."],
    },
    "rpcbind": {
        "checks": [("rpcinfo", "rpcinfo -p {ip}"),
                   ("showmount", "showmount -e {ip}"),
                   ("nmap", "nmap -Pn {sU} -p{port} --script "
                            "rpcinfo,nfs-showmount {ip}")],
        "msf": ["auxiliary/scanner/nfs/nfsmount"],
        "manual": [
            "For each export: `mount -t nfs TARGET:/export /mnt/x -o ro` and "
            "check for world-readable data / no_root_squash.",
        ],
    },
    "nfs": {
        "checks": [("showmount", "showmount -e {ip}"),
                   ("nmap", "nmap -Pn -p111,{port} --script "
                            "nfs-showmount,nfs-ls,nfs-statfs {ip}")],
        "manual": [
            "Mount read-only to confirm: "
            "`mount -t nfs TARGET:/export /mnt/x -o ro`.",
        ],
    },
    "msrpc": {
        "checks": [("impacket-rpcdump", "impacket-rpcdump -port {port} {ip}")],
        "msf": ["auxiliary/scanner/dcerpc/endpoint_mapper"],
        "manual": [
            "Review endpoints for coercion/relay surface (MS-RPRN, MS-EFSR).",
        ],
    },
    "smb": {
        "checks": [("enum4linux-ng", "enum4linux-ng -A {ip}"),
                   ("smbclient", "smbclient -N -L //{ip}/ -p {port}"),
                   ("nxc", "nxc smb {ip} --port {port} -u '' -p '' --shares"),
                   ("nmap", "nmap -Pn -p{port} --script smb-os-discovery,"
                            "smb-security-mode,smb2-security-mode,"
                            "smb-enum-shares,smb-vuln-ms17-010 {ip}")],
        "msf": ["auxiliary/scanner/smb/smb_version",
                "auxiliary/scanner/smb/smb_enumshares",
                "auxiliary/scanner/smb/smb_enumusers",
                "auxiliary/scanner/smb/smb_ms17_010"],
        "login": "auxiliary/scanner/smb/smb_login",
        "manual": [
            "Browse readable shares: `smbclient -N //TARGET/Share` → `ls`, "
            "`get` a sample file as evidence.",
            "Signing not required (`signing:False`) → NTLM relay potential.",
            "Confirm any MS17-010 hit before reporting.",
        ],
    },
    "snmp": {
        "checks": [("snmpwalk", "snmpwalk -v2c -c public -t 3 -r 1 "
                                "{ip}:{port} 1.3.6.1.2.1.1"),
                   ("snmpwalk", "snmpwalk -v2c -c public -t 3 -r 1 "
                                "{ip}:{port} 1.3.6.1.2.1.25.4.2.1.2"),
                   ("snmpwalk", "snmpwalk -v2c -c public -t 3 -r 1 "
                                "{ip}:{port} 1.3.6.1.4.1.77.1.2.25"),
                   ("nmap", "nmap -Pn -sU -p{port} --script "
                            "snmp-info,snmp-sysdescr {ip}")],
        "msf": ["auxiliary/scanner/snmp/snmp_enum"],
        "login": "auxiliary/scanner/snmp/snmp_login",
        "manual": [
            "Data returned for `public` → default community string (finding).",
            "Community-string guessing is opt-in: `onesixtyone -c "
            "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt "
            "TARGET`.",
        ],
    },
    "ldap": {
        "checks": [("ldapsearch", "ldapsearch -x -H {ldap}://{ip}:{port} "
                                  "-s base -b '' '*' +"),
                   ("nmap", "nmap -Pn -p{port} --script ldap-rootdse {ip}")],
        "manual": [
            "If anonymous bind works, dump a naming context: "
            "`ldapsearch -x -H ldap://TARGET:PORT -b '<namingContext>'`.",
        ],
    },
    "rdp": {
        "checks": [("nmap", "nmap -Pn -p{port} --script "
                            "rdp-ntlm-info,rdp-enum-encryption {ip}")],
        "msf": ["auxiliary/scanner/rdp/rdp_scanner"],
        "manual": [
            "`xfreerdp /v:TARGET:PORT` → note NLA requirement and certificate.",
        ],
    },
    "mssql": {
        "checks": [("nmap", "nmap -Pn -p{port} --script ms-sql-info,"
                            "ms-sql-ntlm-info --script-args "
                            "mssql.instance-port={port} {ip}")],
        "msf": ["auxiliary/scanner/mssql/mssql_ping"],
        "login": "auxiliary/scanner/mssql/mssql_login",
        "manual": [
            "Try blank/`sa` creds: `impacket-mssqlclient sa@TARGET -port PORT`.",
        ],
    },
    "mysql": {
        "checks": [("nmap", "nmap -Pn -p{port} --script mysql-info {ip}")],
        "risky": [("nmap", "nmap -Pn -p{port} --script "
                           "mysql-empty-password {ip}"),
                  ("mysql", "mysql -h {ip} -P {port} -u root --skip-password "
                            "-e 'select user();'")],
        "risky_finding": "mysql-empty",
        "msf": ["auxiliary/scanner/mysql/mysql_version"],
        "login": "auxiliary/scanner/mysql/mysql_login",
        "manual": ["Try root/blank: `mysql -h TARGET -P PORT -u root`."],
    },
    "postgres": {
        "msf": ["auxiliary/scanner/postgres/postgres_version"],
        "login": "auxiliary/scanner/postgres/postgres_login",
        "manual": ["Try postgres/postgres: "
                   "`psql -h TARGET -p PORT -U postgres`."],
    },
    "oracle": {
        "checks": [("nmap", "nmap -Pn -p{port} --script oracle-tns-version {ip}")],
        "msf": ["auxiliary/scanner/oracle/tnslsnr_version"],
        "manual": [
            "SID guessing + default creds (opt-in): "
            "`odat all -s TARGET -p PORT`.",
        ],
    },
    "vnc": {
        "checks": [("nmap", "nmap -Pn -p{port} --script "
                            "vnc-info,realvnc-auth-bypass {ip}")],
        "msf": ["auxiliary/scanner/vnc/vnc_none_auth"],
        "login": "auxiliary/scanner/vnc/vnc_login",
        "manual": ["`vncviewer TARGET::PORT` → confirm no-auth/weak password."],
    },
    "winrm": {
        "checks": [("curl", "curl -sk -m 10 -i {scheme}://{ip}:{port}/wsman")],
        "msf": ["auxiliary/scanner/winrm/winrm_auth_methods"],
        "login": "auxiliary/scanner/winrm/winrm_login",
        "manual": ["With creds: `evil-winrm -i TARGET -P PORT -u user -p pass`."],
    },
    "redis": {
        "checks": [("redis-cli", "redis-cli -h {ip} -p {port} INFO server"),
                   ("nmap", "nmap -Pn -p{port} --script redis-info {ip}")],
        "msf": ["auxiliary/scanner/redis/redis_server"],
        "manual": ["`redis-cli -h TARGET -p PORT` → `config get dir`; "
                   "unauthenticated access is a finding."],
    },
    "mongodb": {
        "checks": [("nmap", "nmap -Pn -p{port} --script "
                            "mongodb-info,mongodb-databases {ip}")],
        "login": "auxiliary/scanner/mongodb/mongodb_login",
        "manual": ["`mongosh --host TARGET --port PORT` → `show dbs` "
                   "without auth = finding."],
    },
    "elasticsearch": {
        "checks": [("curl", "curl -sk -m 10 {scheme}://{ip}:{port}/"),
                   ("curl", "curl -sk -m 10 {scheme}://{ip}:{port}/_cat/indices?v")],
        "manual": ["Unauthenticated index listing → check indices for "
                   "sensitive data."],
    },
    "memcached": {
        "checks": [("nmap", "nmap -Pn {sU} -p{port} --script memcached-info {ip}")],
        "manual": ["Unauthenticated stats → finding; UDP 11211 exposed → "
                   "amplification risk."],
    },
    "docker": {
        "checks": [("curl", "curl -sk -m 10 {scheme}://{ip}:{port}/version")],
        "msf": ["auxiliary/scanner/http/docker_version"],
        "manual": ["Unauthenticated Docker API = host root: "
                   "`docker -H tcp://TARGET:PORT ps`."],
    },
    "ipmi": {
        "checks": [("nmap", "nmap -Pn -sU -p{port} --script "
                            "ipmi-version,ipmi-cipher-zero {ip}")],
        "msf": ["auxiliary/scanner/ipmi/ipmi_version",
                "auxiliary/scanner/ipmi/ipmi_cipher_zero"],
        "manual": ["RAKP hash retrieval is opt-in: "
                   "`auxiliary/scanner/ipmi/ipmi_dumphashes`."],
    },
    "rsync": {
        "checks": [("rsync", "rsync --list-only --timeout=20 rsync://{ip}:{port}/"),
                   ("nmap", "nmap -Pn -p{port} --script rsync-list-modules {ip}")],
        "msf": ["auxiliary/scanner/rsync/modules_list"],
        "manual": ["`rsync --list-only rsync://TARGET:PORT/<module>/` "
                   "for each module — readable without auth = finding."],
    },
    "rmi": {
        "checks": [("nmap", "nmap -Pn -p{port} --script rmi-dumpregistry {ip}")],
        "risky": [("nmap", "nmap -Pn -p{port} --script "
                           "rmi-vuln-classloader {ip}")],
        "risky_finding": "nse:rmi-vuln-classloader",
        "msf": ["auxiliary/scanner/misc/java_rmi_server"],
        "manual": ["Deeper RMI enumeration: `remote-method-guesser` (rmg)."],
    },
    "sip": {
        "checks": [("nmap", "nmap -Pn {sU} -p{port} --script sip-methods {ip}")],
        "msf": ["auxiliary/scanner/sip/options"],
        "manual": ["Extension enumeration (opt-in): `svwar` from sipvicious."],
    },
    "proxy": {
        "checks": [("nmap", "nmap -Pn -p{port} --script http-headers {ip}")],
        # http-open-proxy makes the target fetch an outside site.
        "risky": [("nmap", "nmap -Pn -p{port} --script http-open-proxy {ip}")],
        "risky_finding": "open-proxy",
        "manual": ["Confirm open proxy: "
                   "`curl -x http://TARGET:PORT http://example.com`."],
    },
    "rpc": {
        "checks": [("nmap", "nmap -Pn {sU} -p111,{port} --script rpcinfo {ip}")],
        "manual": ["RPC program on a dynamic port — see rpcinfo on 111 for "
                   "what it is; NFS-related programs are covered by the NFS steps."],
    },
    "drb": {
        "manual": ["Ruby DRb with no ACL allows remote code execution — "
                   "confirm with a DRb client (`DRbObject.new_with_uri("
                   "'druby://TARGET:PORT')`), opt-in."],
    },
    "x11": {
        "checks": [("nmap", "nmap -Pn -p{port} --script x11-access {ip}")],
        "msf": ["auxiliary/scanner/x11/open_x11"],
        "manual": ["Open X server → screenshot/keylog risk: "
                   "`xwd -root -display TARGET:0 -out x.xwd`."],
    },
    "irc": {
        "checks": [("nmap", "nmap -Pn -p{port} --script irc-info {ip}")],
        "manual": ["UnrealIRCd: confirm 3.2.8.1 backdoor by hand "
                   "(`irc-unrealircd-backdoor` NSE executes a command — opt-in)."],
    },
    "ajp": {
        "checks": [("nmap", "nmap -Pn -p{port} --script "
                            "ajp-methods,ajp-headers {ip}")],
        "manual": ["Ghostcat (CVE-2020-1938) file read — opt-in: "
                   "`auxiliary/admin/http/tomcat_ghostcat`."],
    },
    "bindshell": {
        "manual": ["CRITICAL if real: `nc TARGET PORT` — an unauthenticated "
                   "shell. Capture `id` output as evidence."],
    },
    "distcc": {
        "manual": ["distccd CVE-2004-2687 command exec — confirm with "
                   "`nmap -p PORT --script distcc-cve2004-2687 TARGET` (runs a "
                   "command, opt-in)."],
    },
    "rexec": {"manual": ["Legacy r-service: cleartext + trust-based auth; "
                         "test `rexec`/`rsh` by hand."]},
    "rlogin": {"manual": ["Legacy r-service: `rlogin -l root TARGET` — "
                          "check .rhosts trust."]},
    "rsh": {"manual": ["Legacy r-service: `rsh -l root TARGET id`."]},
    "ssl": {
        "checks": [("nmap", "nmap -Pn -p{port} --script ssl-enum-ciphers,"
                            "ssl-cert,sslv2,ssl-heartbleed,ssl-poodle,"
                            "ssl-ccs-injection,ssl-dh-params {ip}"),
                   ("sslscan", "sslscan --no-colour {starttls} {ip}:{port}")],
        "manual": ["`sslscan TARGET:PORT` / `testssl.sh TARGET:PORT` — confirm "
                   "protocols, ciphers and certificate.",
                   "`openssl s_client -connect TARGET:PORT -tls1` — a "
                   "handshake proves TLS 1.0 is accepted (use -tls1_1, "
                   "-ssl3 likewise)."],
    },
    "finger": {
        "checks": [("nmap", "nmap -Pn -p{port} --script finger {ip}")],
        "manual": ["`finger @TARGET` and `finger root@TARGET` — user "
                   "enumeration."],
    },
    "tftp": {
        "checks": [("nmap", "nmap -Pn -sU -p{port} --script tftp-version {ip}")],
        "manual": ["`tftp TARGET` → `get` a known config file name (opt-in) — "
                   "TFTP has no authentication."],
    },
    "kerberos": {
        "manual": ["Kerberos usually means a domain controller. User "
                   "enumeration / AS-REP roasting need a userlist (opt-in): "
                   "`kerbrute userenum -d <domain> --dc TARGET users.txt`."],
    },
    "nntp": {
        "checks": [("nmap", "nmap -Pn -p{port} --script nntp-ntlm-info {ip}")],
        "manual": ["`nc TARGET PORT` → `LIST` — readable without auth?"],
    },
    "ntp": {
        "checks": [("nmap", "nmap -Pn -sU -p{port} --script ntp-info {ip}")],
        "manual": ["`ntpq -c rv TARGET` — version/system disclosure; monlist "
                   "(amplification) check is opt-in: `ntpdc -n -c monlist TARGET`."],
    },
    "netbios-ns": {
        "checks": [("nmap", "nmap -Pn -sU -p{port} --script nbstat {ip}"),
                   ("nmblookup", "nmblookup -A {ip}")],
        "manual": ["NetBIOS name table → hostname, domain/workgroup, logged-on "
                   "user names."],
    },
    "ike": {
        "checks": [("nmap", "nmap -Pn -sU -p{port} --script ike-version {ip}")],
        "manual": ["`ike-scan -M TARGET` and aggressive mode `ike-scan -A -M "
                   "TARGET` (opt-in) — aggressive mode leaks a crackable PSK hash."],
    },
    "rtsp": {
        "checks": [("nmap", "nmap -Pn -p{port} --script rtsp-methods {ip}")],
        "manual": ["`ffplay rtsp://TARGET:PORT/` — camera stream without auth?"],
    },
    "ipp": {
        "checks": [("nmap", "nmap -Pn -p{port} --script cups-info,"
                            "cups-queue-info {ip}")],
        "manual": ["Browse `http://TARGET:PORT/` — CUPS admin reachable?"],
    },
    "jetdirect": {
        "manual": ["Raw printing port — `nc TARGET PORT` accepts jobs without "
                   "auth; PJL info leak can be checked with PRET (opt-in)."],
    },
    "vmware": {
        "checks": [("nmap", "nmap -Pn -p{port} --script vmware-version {ip}")],
        "manual": ["Map the ESXi/vCenter build to VMware advisories."],
    },
    "mqtt": {
        "checks": [("nmap", "nmap -Pn -p{port} --script mqtt-subscribe {ip}")],
        "manual": ["`mosquitto_sub -h TARGET -p PORT -t '#' -v` — anonymous "
                   "read of all topics?"],
    },
    "upnp": {
        "checks": [("nmap", "nmap -Pn -sU -p{port} --script upnp-info {ip}")],
        "manual": ["Fetch the device description URL from upnp-info output."],
    },
    "zookeeper": {
        "checks": [("nmap", "nmap -Pn -sV -p{port} {ip}")],
        "manual": ["`echo srvr | nc TARGET PORT` and `echo dump | nc TARGET "
                   "PORT` — unauthenticated cluster info?"],
    },
    "etcd": {
        "checks": [("curl", "curl -sk -m 10 {scheme}://{ip}:{port}/version")],
        "manual": ["`etcdctl --endpoints=http://TARGET:PORT get / --prefix "
                   "--keys-only` — unauthenticated key read = secrets exposure."],
    },
    "kubernetes": {
        "checks": [("curl", "curl -sk -m 10 https://{ip}:{port}/version"),
                   ("curl", "curl -sk -m 10 https://{ip}:{port}/api/v1/namespaces")],
        "manual": ["Anonymous API access beyond /version → check RBAC for "
                   "`system:anonymous`."],
    },
    "kubelet": {
        "checks": [("curl", "curl -sk -m 10 https://{ip}:{port}/pods")],
        "manual": ["A PodList from /pods without a token = anonymous kubelet "
                   "API (critical)."],
    },
    "iscsi": {
        "checks": [("nmap", "nmap -Pn -p{port} --script iscsi-info {ip}")],
        "manual": ["`iscsiadm -m discovery -t st -p TARGET` — targets "
                   "discoverable without CHAP?"],
    },
    "svn": {
        "checks": [("svn", "svn ls --non-interactive svn://{ip}:{port}/")],
        "manual": ["`svn log svn://TARGET:PORT/` — anonymous source read?"],
    },
    "git": {
        "manual": ["`git ls-remote git://TARGET:PORT/<repo>` — guess repo "
                   "names; anonymous clone = source exposure."],
    },
    "mdns": {
        "checks": [("nmap", "nmap -Pn -sU -p{port} --script "
                            "dns-service-discovery {ip}")],
        "manual": ["Service names/hostnames leaked via mDNS."],
    },
    "amqp": {
        "checks": [("nmap", "nmap -Pn -p{port} --script amqp-info {ip}")],
        "manual": ["Try guest/guest on the broker / management UI (15672)."],
    },
    "couchdb": {
        "checks": [("nmap", "nmap -Pn -p{port} --script "
                            "couchdb-databases,couchdb-stats {ip}"),
                   ("curl", "curl -sk -m 10 {scheme}://{ip}:{port}/_all_dbs")],
        "manual": ["Database list readable without auth → check for "
                   "sensitive documents."],
    },
    "cassandra": {
        "checks": [("nmap", "nmap -Pn -p{port} --script cassandra-info {ip}")],
        "manual": ["`cqlsh TARGET PORT` — anonymous login accepted?"],
    },
    "jdwp": {
        "checks": [("nmap", "nmap -Pn -p{port} --script jdwp-version {ip}")],
        "manual": ["An exposed Java debug port allows code execution — "
                   "confirm scope before going further."],
    },
    "web": {
        "checks": [("curl", "curl -sk -m 10 -I {scheme}://{ip}:{port}/"),
                   ("whatweb", "whatweb -a 1 --color=never "
                               "{scheme}://{ip}:{port}/"),
                   ("nmap", "nmap -Pn -p{port} --script http-title,"
                            "http-headers,http-methods,http-robots.txt {ip}")],
        "msf": ["auxiliary/scanner/http/http_version",
                "auxiliary/scanner/http/title"],
        "manual": [
            "Open BOTH http:// and https://TARGET:PORT; cross-check "
            "web-report.html.",
            "Admin panels, directory listing, verbose errors, exposed "
            "`.git`/backups; default creds on any login panel.",
            "Heavier scans (opt-in): `nikto -h URL`, `nuclei -u URL`, "
            "`ffuf -u URL/FUZZ -w .../common.txt`.",
        ],
    },
}

# Modules where the SSL datastore option matters for https ports.
SSL_AWARE = {"web", "winrm", "docker"}

# ---------------------------------------------------------------------------
# Findings catalogue. Each entry tells the tester how to reproduce the result
# by hand ({ip}/{port}/{share} filled per affected host), what to expect, what
# to do next, and the fix. "msf" is a REFERENCE only — never run by the script.
# ---------------------------------------------------------------------------

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

FINDING_INFO = {
    # ---- version / service based (from the nmap scan itself)
    "vsftpd-234": dict(
        sev="Critical", title="vsftpd 2.3.4 backdoored release (CVE-2011-2523)",
        why="This release shipped with a backdoor that opens a root shell.",
        repro=["nmap -Pn -sV -p{port} {ip}"],
        expect="Version column shows `vsftpd 2.3.4`.",
        next="Version match is strong evidence. Confirm within scope using the "
             "Metasploit module below (see docs/workflow/MANUAL_METASPLOIT.md).",
        fix="Replace with a current vsftpd build from the vendor.",
        msf="exploit/unix/ftp/vsftpd_234_backdoor"),
    "proftpd-133c": dict(
        sev="Critical", title="ProFTPD 1.3.3c backdoored release",
        why="The 1.3.3c source tarball was trojaned with a remote root backdoor.",
        repro=["nmap -Pn -sV -p{port} {ip}"],
        expect="Version column shows `ProFTPD 1.3.3c`.",
        next="Confirm within scope (see docs/workflow/MANUAL_METASPLOIT.md).",
        fix="Upgrade ProFTPD.", msf="exploit/unix/ftp/proftpd_133c_backdoor"),
    "unrealircd": dict(
        sev="Critical", title="UnrealIRCd — 3.2.8.1 backdoor (CVE-2010-2075)",
        why="UnrealIRCd 3.2.8.1 tarballs contained a command-execution backdoor.",
        repro=["nmap -Pn -sV -p{port} {ip}",
               "nmap -Pn -p{port} --script irc-info {ip}"],
        expect="UnrealIRCd banner; irc-info shows the server version.",
        next="If the version is 3.2.8.1 the host is vulnerable. Confirm within "
             "scope (see docs/workflow/MANUAL_METASPLOIT.md).",
        fix="Upgrade UnrealIRCd and verify release signatures.",
        msf="exploit/unix/irc/unreal_ircd_3281_backdoor"),
    "samba-usermap": dict(
        sev="Critical", title="Samba 3.0.20-3.0.25 usermap_script (CVE-2007-2447)",
        why="Shell metacharacters in the username give command execution as root.",
        repro=["nmap -Pn -p{port} --script smb-os-discovery {ip}"],
        expect="OS/LanMan shows `Samba 3.0.20` – `3.0.25`.",
        next="Confirm within scope (see docs/workflow/MANUAL_METASPLOIT.md).",
        fix="Upgrade Samba (3.0.25a or later; ideally a supported release).",
        msf="exploit/multi/samba/usermap_script"),
    "distcc": dict(
        sev="Critical", title="distccd exposed (CVE-2004-2687)",
        why="distccd without host restrictions runs arbitrary commands.",
        repro=["nmap -Pn -sV -p{port} {ip}"],
        expect="Service shows `distccd`.",
        next="Confirm within scope (see docs/workflow/MANUAL_METASPLOIT.md).",
        fix="Restrict with --allow to build hosts only, or disable distccd.",
        msf="exploit/unix/misc/distcc_exec"),
    "bindshell": dict(
        sev="Critical", title="Unauthenticated shell listening",
        why="Anyone who connects gets a shell — usually root.",
        repro=["nc -nv {ip} {port}     # then type: id"],
        expect="A `uid=…` line comes back with no login prompt.",
        next="Capture the `id` output as evidence; treat the host as "
             "compromised and escalate to the client immediately.",
        fix="Kill the listener, find how it was planted, rebuild the host."),
    "drb": dict(
        sev="High", title="Ruby DRb service exposed",
        why="DRb without an ACL lets clients call methods on server objects "
            "(code execution).",
        repro=["nmap -Pn -sV -p{port} {ip}"],
        expect="Service shows `drb` / `Ruby DRb RMI`.",
        next="Verify by hand within scope (see docs/reference/MANUAL_VERIFICATION.md → DRb).",
        fix="Bind DRb to localhost or set a strict ACL."),
    "java-rmi": dict(
        sev="High", title="Java RMI registry exposed",
        why="Default RMI configs may load remote classes (code execution).",
        repro=["nmap -Pn -p{port} --script rmi-dumpregistry,rmi-vuln-classloader {ip}"],
        expect="Registry contents listed; classloader result `VULNERABLE` if "
               "remote class loading is enabled.",
        next="Confirm within scope (see docs/workflow/MANUAL_METASPLOIT.md).",
        fix="Firewall the registry; disable remote class loading "
            "(java.rmi.server.useCodebaseOnly=true).",
        msf="exploit/multi/misc/java_rmi_server"),
    "tomcat": dict(
        sev="Info", title="Apache Tomcat — manager application may be exposed",
        why="Tomcat Manager with default credentials allows WAR deployment.",
        repro=["curl -sk -o /dev/null -w '%{{http_code}}\\n' {scheme}://{ip}:{port}/manager/html"],
        expect="401 = manager present (login prompt); 404 = not deployed.",
        next="If 401, test default credentials (opt-in, see docs/workflow/MANUAL_METASPLOIT.md).",
        fix="Remove the manager app or restrict it to admin networks with "
            "strong credentials.",
        msf="auxiliary/scanner/http/tomcat_mgr_login"),
    "jdwp": dict(
        sev="High", title="Java debug port (JDWP) exposed",
        why="JDWP has no authentication and allows code execution in the JVM.",
        repro=["nmap -Pn -p{port} --script jdwp-version {ip}"],
        expect="jdwp-version prints the JVM version.",
        next="Confirm scope before further testing.",
        fix="Disable -agentlib:jdwp in production or bind it to localhost."),
    "telnet": dict(
        sev="Medium", title="Cleartext remote login: Telnet",
        why="Credentials and sessions travel unencrypted.",
        repro=["nc -nv {ip} {port}"],
        expect="A telnet negotiation / login banner.",
        next="Note the device type from the banner; try vendor default "
             "credentials if in scope.",
        fix="Disable Telnet; use SSH."),
    "r-services": dict(
        sev="High", title="Legacy r-services exposed (rexec/rlogin/rsh)",
        why="Cleartext and host-trust based authentication (.rhosts).",
        repro=["nmap -Pn -sV -p{port} {ip}"],
        expect="Service shows exec / login / shell.",
        next="Test trust by hand (see docs/reference/MANUAL_VERIFICATION.md → r-services).",
        fix="Disable rexecd/rlogind/rshd."),
    # ---- from automated check output
    "weak-creds": dict(
        sev="High", title="Weak / default credentials accepted",
        why="A guessed or default username/password logs in — direct access "
            "to the service, often a foothold on the host.",
        repro=["# log in with the credentials shown in the evidence line, e.g.",
               "# ssh <user>@{ip} -p {port}   /   ftp -P {port} {ip}"],
        expect="A successful login with the listed credentials.",
        next="Record what the account can reach; stop there unless "
             "post-login testing is in scope.",
        fix="Change the password / disable the default account; enforce a "
            "password policy and lockout."),
    "ftp-anon": dict(
        sev="Medium", title="FTP anonymous login allowed",
        why="Anyone can read (and possibly write) files on the server.",
        repro=["nmap -Pn -p{port} --script ftp-anon {ip}",
               "ftp -P {port} {ip}     # user: anonymous  pass: anything → ls -la"],
        expect="`Anonymous FTP login allowed (FTP code 230)`.",
        next="List what is readable; check write access with a harmless test "
             "file and delete it afterwards.",
        fix="Disable anonymous FTP (vsftpd: anonymous_enable=NO)."),
    "smb-null": dict(
        sev="Medium", title="SMB null session allowed",
        why="Unauthenticated users can enumerate users, groups and shares.",
        repro=["smbclient -N -L //{ip}/ -p {port}", "enum4linux-ng -A {ip}"],
        expect="Share list returned without credentials; enum4linux-ng says the "
               "server allows username '' / password ''.",
        next="Record the users/shares enumerated as evidence.",
        fix="Disable anonymous access (RestrictAnonymous / `restrict "
            "anonymous = 2`)."),
    "smb-share-anon": dict(
        sev="High", title="SMB share accessible anonymously",
        why="Files are readable — or writable — without credentials.",
        repro=["smbclient -N //{ip}/{share} -p {port} -c 'ls'",
               "nmap -Pn -p{port} --script smb-enum-shares {ip}"],
        expect="Directory listing without a password; smb-enum-shares shows "
               "`Anonymous access: READ` or `READ/WRITE`.",
        next="Look for sensitive files; for READ/WRITE, prove write with a "
             "harmless test file and remove it.",
        fix="Remove guest/anonymous access from the share."),
    "smb-signing": dict(
        sev="Medium", title="SMB signing not required",
        why="Enables NTLM relay attacks against this host.",
        repro=["nmap -Pn -p{port} --script smb2-security-mode,smb-security-mode {ip}",
               "nxc smb {ip} --port {port}"],
        expect="`message signing enabled but not required` / `signing:False`.",
        next="Report; relay testing is a separate, opt-in activity.",
        fix="Require SMB signing (GPO: Microsoft network server: Digitally "
            "sign communications (always))."),
    "smtp-vrfy": dict(
        sev="Low", title="SMTP VRFY enabled (user enumeration)",
        why="Lets an attacker confirm valid local usernames.",
        repro=["nc -nv {ip} {port}     # then: EHLO test  /  VRFY root"],
        expect="`252` or `250` for an existing user, `550` for a missing one.",
        next="Note any confirmed users for later credential testing (opt-in).",
        fix="Disable VRFY/EXPN (Postfix: disable_vrfy_command = yes)."),
    "smtp-user-enum": dict(
        sev="Low", title="SMTP user enumeration (usernames confirmed)",
        why="The server confirms which usernames exist — a ready list for "
            "password guessing and phishing.",
        repro=["nmap -Pn -p{port} --script smtp-enum-users {ip}"],
        expect="Usernames listed under `smtp-enum-users:`.",
        next="Note the users; credential testing is a separate, opt-in step.",
        fix="Disable VRFY/EXPN and give the same reply to RCPT TO for valid "
            "and invalid users."),
    "smtp-open-relay": dict(
        sev="High", title="SMTP open relay",
        why="Anyone can send mail through the server to outside domains — "
            "spam, phishing from a trusted IP, blocklisting.",
        repro=["nmap -Pn -p{port} --script smtp-open-relay {ip}"],
        expect="`Server is an open relay (N/16 tests)` with the accepted "
               "MAIL FROM / RCPT TO combinations.",
        next="Report the accepted combinations; do not send real mail "
             "through it.",
        fix="Allow relaying only for authenticated users / internal networks "
            "(Postfix: smtpd_relay_restrictions)."),
    "mysql-empty": dict(
        sev="Critical", title="MySQL account with empty password",
        why="Full database access without a password.",
        repro=["nmap -Pn -p{port} --script mysql-empty-password {ip}",
               "mysql -h {ip} -P {port} -u root --skip-password -e 'select user();'"],
        expect="`root account has empty password`; the mysql client logs in.",
        next="List databases (`show databases;`) as evidence only.",
        fix="Set strong passwords; bind MySQL to localhost or restrict hosts."),
    "x11-open": dict(
        sev="High", title="X11 server allows unauthenticated access",
        why="Remote screenshots, keystroke capture and input injection.",
        repro=["nmap -Pn -p{port} --script x11-access {ip}"],
        expect="`X server access is granted`.",
        next="Evidence: `xdpyinfo -display {ip}:0` output.",
        fix="Disable TCP listening (-nolisten tcp) and use xauth."),
    "dns-recursion": dict(
        sev="Medium", title="DNS open recursion",
        why="Usable for DNS amplification and cache poisoning.",
        repro=["dig @{ip} -p {port} example.com A +recurse"],
        expect="An answer section with the `ra` flag set.",
        next="Report.", fix="Restrict recursion to internal clients."),
    "nfs-exports": dict(
        sev="Medium", title="NFS exports visible",
        why="Exports open to everyone may expose or allow modifying data.",
        repro=["showmount -e {ip}"],
        expect="An export list; `*` means any host may mount.",
        next="Mount read-only to confirm access "
             "(see docs/reference/MANUAL_VERIFICATION.md → NFS).",
        fix="Restrict exports to specific hosts; use root_squash."),
    "nfs-root-export": dict(
        sev="Critical", title="Root filesystem (/) exported over NFS",
        why="The whole filesystem can be mounted remotely; with write access "
            "an attacker can plant SSH keys or edit system files.",
        repro=["showmount -e {ip}",
               "nmap -Pn -p111,2049 --script nfs-showmount,nfs-ls {ip}"],
        expect="The export list contains `/` (`*` = any host may mount).",
        next="Mount read-only and record the listing as evidence "
             "(see docs/reference/MANUAL_VERIFICATION.md → NFS).",
        fix="Never export /; export only the directories needed, to "
            "specific hosts."),
    "nfs-writable": dict(
        sev="High", title="NFS export writable without authentication",
        why="Any host that can mount the export can create, change or delete "
            "files on it.",
        repro=["nmap -Pn -p111,2049 --script nfs-ls {ip}"],
        expect="nfs-ls shows `access: ... Modify Extend Delete` for the "
               "volume listed under Affected.",
        next="Mount it and prove write access with a harmless test file, then "
             "delete it (see docs/reference/MANUAL_VERIFICATION.md → NFS).",
        fix="Export read-only or to specific hosts only; keep root_squash."),
    "redis-unauth": dict(
        sev="High", title="Redis without authentication",
        why="Full data access; often leads to code execution.",
        repro=["redis-cli -h {ip} -p {port} INFO server"],
        expect="`redis_version:` and server info without AUTH.",
        next="Report; do not write keys.",
        fix="Set requirepass / ACLs and bind to localhost."),
    "docker-unauth": dict(
        sev="Critical", title="Docker API without authentication",
        why="Equivalent to root on the host.",
        repro=["curl -sk {scheme}://{ip}:{port}/version"],
        expect="JSON with `ApiVersion`.",
        next="Report immediately; do not start containers.",
        fix="Disable the TCP socket or require TLS client certificates."),
    "es-unauth": dict(
        sev="High", title="Elasticsearch without authentication",
        why="All indexed data is readable (and writable).",
        repro=["curl -sk {scheme}://{ip}:{port}/",
               "curl -sk '{scheme}://{ip}:{port}/_cat/indices?v'"],
        expect="Cluster JSON with `cluster_name`; index list.",
        next="Note index names only as evidence.",
        fix="Enable X-Pack security / put behind auth."),
    "snmp-public": dict(
        sev="Medium", title="SNMP default community string `public`",
        why="Discloses system details, processes, users and network config.",
        repro=["snmpwalk -v2c -c public {ip}:{port} 1.3.6.1.2.1.1"],
        expect="sysDescr / sysName values returned.",
        next="Check whether `private` (write) also works — opt-in.",
        fix="Change community strings or use SNMPv3 with auth."),
    "open-proxy": dict(
        sev="Medium", title="Open HTTP proxy",
        why="Anyone can relay traffic through the host.",
        repro=["curl -s -x http://{ip}:{port} http://example.com -o /dev/null -w '%{{http_code}}\\n'"],
        expect="`Potentially OPEN proxy` (nmap) / `200` through the proxy "
               "(curl).",
        next="Report.", fix="Require authentication or restrict clients."),
    "mqtt-anon": dict(
        sev="Medium", title="MQTT broker allows anonymous subscribe",
        why="Messages on all topics are readable without credentials.",
        repro=["nmap -Pn -p{port} --script mqtt-subscribe {ip}"],
        expect="Topic names and payloads listed.",
        next="Note topics as evidence.", fix="Disable anonymous access."),
    "couchdb-unauth": dict(
        sev="High", title="CouchDB without authentication",
        why="Databases readable without credentials.",
        repro=["curl -sk {scheme}://{ip}:{port}/_all_dbs"],
        expect="A JSON list of database names.",
        next="Note names only.", fix="Enable authentication (admin party off)."),
    "kubelet-unauth": dict(
        sev="Critical", title="Kubelet API allows anonymous access",
        why="Pod listing and command execution in containers.",
        repro=["curl -sk https://{ip}:{port}/pods"],
        expect="JSON `\"kind\":\"PodList\"`.",
        next="Report immediately.",
        fix="Set --anonymous-auth=false and webhook authorization."),
    "etcd-unauth": dict(
        sev="High", title="etcd reachable without authentication",
        why="etcd usually holds cluster secrets.",
        repro=["curl -sk {scheme}://{ip}:{port}/version"],
        expect="JSON with `etcdserver`.",
        next="Check key listing by hand (see docs/reference/MANUAL_VERIFICATION.md).",
        fix="Enable client cert auth; firewall the port."),
    # ---- SSL/TLS
    "tls-old-proto": dict(
        sev="Medium", title="Deprecated SSL/TLS protocol versions enabled",
        why="SSLv2/SSLv3/TLS 1.0/1.1 have known weaknesses (POODLE, BEAST) "
            "and fail compliance (PCI DSS).",
        repro=["nmap -Pn -p{port} --script ssl-enum-ciphers {ip}",
               "openssl s_client -connect {ip}:{port} -tls1 </dev/null"],
        expect="Protocol sections for the versions listed under Detail; "
               "openssl completes a handshake.",
        next="Report with the protocol list.",
        fix="Allow only TLS 1.2 and 1.3."),
    "tls-weak-cipher": dict(
        sev="Medium", title="Weak TLS cipher suites accepted",
        why="Weak/export/RC4/3DES ciphers can be broken or downgraded.",
        repro=["nmap -Pn -p{port} --script ssl-enum-ciphers {ip}",
               "sslscan {ip}:{port}"],
        expect="`least strength:` grade shown under Detail (C or worse).",
        next="Report the weakest suites listed.",
        fix="Disable RC4, 3DES, EXPORT, NULL and CBC-SHA1 suites."),
    "tls-cert-expired": dict(
        sev="Medium", title="TLS certificate expired",
        why="Clients get warnings; users learn to click through them.",
        repro=["nmap -Pn -p{port} --script ssl-cert {ip}",
               "openssl s_client -connect {ip}:{port} </dev/null 2>/dev/null | openssl x509 -noout -dates"],
        expect="`Not valid after` date in the past (see Detail).",
        next="Report.", fix="Renew the certificate."),
    "tls-self-signed": dict(
        sev="Low", title="TLS certificate is self-signed",
        why="No trust chain; enables man-in-the-middle without warnings "
            "being meaningful.",
        repro=["nmap -Pn -p{port} --script ssl-cert {ip}"],
        expect="Subject and Issuer are identical.",
        next="Report.", fix="Use a certificate from a trusted CA."),
    "nse-vuln": dict(
        sev="High", title="nmap NSE: vulnerability confirmed",
        why="An nmap vulnerability script reported the host as VULNERABLE.",
        repro=["{cmd}"],
        expect="Script output shows `State: VULNERABLE`.",
        next="Look up the CVE in the script output; confirm within scope.",
        fix="Apply the vendor fix for the listed CVE."),
}

# Per-script severity / why / fix for NSE "State: VULNERABLE" results.
# Scripts not listed fall back to the generic "nse-vuln" entry (High).
NSE_META = {
    "ssl-heartbleed": ("Critical", "Heartbleed (CVE-2014-0160) leaks server "
                       "memory, including private keys and session data.",
                       "Upgrade OpenSSL; revoke and reissue keys/certificates."),
    "ssl-ccs-injection": ("High", "CCS injection (CVE-2014-0224) lets a "
                          "man-in-the-middle decrypt or modify traffic.",
                          "Upgrade OpenSSL."),
    "ssl-poodle": ("Medium", "SSLv3 with CBC ciphers allows POODLE plaintext "
                   "recovery (CVE-2014-3566).", "Disable SSLv3."),
    "ssl-dh-params": ("Medium", "Weak or anonymous Diffie-Hellman key exchange "
                      "allows man-in-the-middle / Logjam.",
                      "Use ECDHE or >=2048-bit DH groups; disable anonymous "
                      "DH suites."),
    "smb-vuln-ms17-010": ("Critical", "MS17-010 (EternalBlue) — remote code "
                          "execution over SMBv1.",
                          "Apply MS17-010 and disable SMBv1."),
    "rmi-vuln-classloader": ("High", "RMI registry loads remote classes — "
                             "remote code execution.",
                             "Disable remote class loading; firewall RMI."),
    "realvnc-auth-bypass": ("Critical", "RealVNC authentication bypass "
                            "(CVE-2006-2369).", "Upgrade RealVNC."),
    "ipmi-cipher-zero": ("High", "IPMI cipher suite 0 accepts any password.",
                         "Disable cipher suite 0 on the BMC."),
}


def finding_info(fid, entries=()):
    """FINDING_INFO entry; NSE results get their own title/severity/fix."""
    if not fid.startswith("nse:"):
        return FINDING_INFO[fid]
    script = fid[4:]
    info = dict(FINDING_INFO["nse-vuln"])
    title = next((e["fmt"]["title"] for e in entries
                  if e["fmt"].get("title")), script)
    info["title"] = f"{title} ({script})"
    if script in NSE_META:
        info["sev"], info["why"], info["fix"] = NSE_META[script]
    return info


# nmap name/product/version regex -> finding id (from the scan itself)
VERSION_RULES = [
    (r"vsftpd 2\.3\.4\b", "vsftpd-234"),
    (r"ProFTPD 1\.3\.3c\b", "proftpd-133c"),
    (r"UnrealIRCd", "unrealircd"),
    (r"Samba smbd 3\.0\.(2[0-5])\b", "samba-usermap"),
    (r"distccd", "distcc"),
    (r"bindshell|root shell", "bindshell"),
    (r"\bdrb\b|Ruby DRb", "drb"),
    (r"java-rmi|rmiregistry", "java-rmi"),
    (r"Tomcat|Coyote", "tomcat"),
    (r"^jdwp\b", "jdwp"),
    (r"^telnet\b", "telnet"),
    (r"^(exec|login|shell)\b", "r-services"),
]

# check-output regex -> finding id
OUTPUT_RULES = [
    (r"Anonymous FTP login allowed", "ftp-anon"),
    (r"message_signing: disabled|signing enabled but not required"
     r"|signing:False", "smb-signing"),
    (r"session using username '', password ''"
     r"|authentication via username '' and password ''", "smb-null"),
    (r"smtp-commands:.*\bVRFY\b", "smtp-vrfy"),
    (r"^\| smtp-enum-users:\s*\n\|[ _]\s+\S", "smtp-user-enum"),
    (r"Server is an open relay", "smtp-open-relay"),
    (r"account has empty password", "mysql-empty"),
    (r"X server access is granted", "x11-open"),
    (r"Recursion appears to be enabled", "dns-recursion"),
    (r"Export list for \S+:\s*\n\s*/|nfs-showmount:\s*\n\|_?\s+/",
     "nfs-exports"),
    (r"redis_version:", "redis-unauth"),
    (r'"ApiVersion"', "docker-unauth"),
    (r'"cluster_name"', "es-unauth"),
    (r"sysDescr\.0|iso\.3\.6\.1\.2\.1\.1\.1\.0", "snmp-public"),
    (r"Potentially OPEN proxy", "open-proxy"),
    (r"mqtt-subscribe:\s*\n\|\s+Topics", "mqtt-anon"),
    (r"^\[\s*\"", "couchdb-unauth"),
    (r'"kind"\s*:\s*"PodList"', "kubelet-unauth"),
    (r'"etcdserver"', "etcd-unauth"),
    # irc-unrealircd-backdoor NSE (hand-run proof, MANDATORY_CHECKS §5)
    (r"Looks like trojaned version of unrealircd", "unrealircd"),
]
# rules that only make sense for one profile (avoid cross-matching)
RULE_PROFILE = {"couchdb-unauth": "couchdb", "etcd-unauth": "etcd",
                "kubelet-unauth": "kubelet"}

# Metasploit result line -> finding id: (module regex, message regex, fid).
# Matched against `[+]` / `[*]` lines of msf-run.log and msf-manual*.log,
# with the module taken from the preceding `use …` / prompt. Messages are
# the modules' own print_good / print_status strings.
MSF_RULES = [
    (r"ftp/ftp_anonymous", r"Anonymous \S+ access", "ftp-anon"),
    (r"smtp/smtp_enum", r"Users found:", "smtp-user-enum"),
    (r"nfs/nfsmount", r"Mountable NFS Export: / ", "nfs-root-export"),
    (r"nfs/nfsmount", r"Mountable NFS Export:", "nfs-exports"),
    (r"smb/smb_enumshares", r"\(DISK\)", "smb-null"),
    (r"smb/smb_version", r"signatures: optional", "smb-signing"),
    (r"smb/smb_ms17_010", r"VULNERABLE to MS17-010", "nse:smb-vuln-ms17-010"),
    (r"misc/java_rmi_server", r"Class Loader Enabled",
     "nse:rmi-vuln-classloader"),
    (r"x11/open_x11", r".", "x11-open"),
    (r"redis/redis_server", r"Found redis", "redis-unauth"),
    (r"http/docker_version", r"Docker Server\] Version", "docker-unauth"),
    (r"couchdb/couchdb_enum", r"Databases:", "couchdb-unauth"),
    (r"etcd/version", r".", "etcd-unauth"),
    (r"mqtt/connect", r"Does not require authentication", "mqtt-anon"),
    (r"http/open_proxy", r"Potentially open proxy", "open-proxy"),
    (r"dns/dns_amp", r"Amplification", "dns-recursion"),
    (r"elasticsearch_enum", r".", "es-unauth"),
    (r"ssl/openssl_heartbleed", r"Heartbeat response with leak",
     "nse:ssl-heartbleed"),
    (r"ssl/openssl_ccs", r"probably vulnerable", "nse:ssl-ccs-injection"),
    (r"ipmi/ipmi_cipher_zero", r"VULNERABLE", "nse:ipmi-cipher-zero"),
    (r"mysql/mysql_login", r"Success: '[^':]*:'", "mysql-empty"),
    # Any login scanner from MANDATORY_CHECKS (hand-run, spooled). A blank
    # MySQL password is mysql-empty above, so this needs a non-empty one.
    (r"_login$", r"Success: '[^':]*:[^']+'|Login Successful", "weak-creds"),
    # r-services trust / password logins print their own wording.
    (r"rservices/(rsh|rlogin|rexec)_login",
     r"with no password|successful with password|rexec '", "weak-creds"),
    (r"smtp/smtp_relay", r"Potential open SMTP relay detected",
     "smtp-open-relay"),
    # Exploit modules (MANDATORY_CHECKS §5): a `[+]` line is either a
    # positive `check` ("The target is vulnerable." / the module's own
    # message) or a working exploit — either way the finding is confirmed.
    (r"^exploit/unix/ftp/vsftpd_234_backdoor$", r".", "vsftpd-234"),
    (r"^exploit/unix/ftp/proftpd_133c_backdoor$", r".", "proftpd-133c"),
    (r"^exploit/unix/irc/unreal_ircd_3281_backdoor$", r".", "unrealircd"),
    (r"^exploit/multi/samba/usermap_script$", r".", "samba-usermap"),
    (r"^exploit/unix/misc/distcc_exec$", r".", "distcc"),
    (r"^exploit/multi/misc/java_jdwp_debugger$", r".", "jdwp"),
    (r"^exploit/multi/misc/java_rmi_server$", r".", "java-rmi"),
    (r"snmp/snmp_enum", r"Connected", "snmp-public"),
]
# Titles for NSE-style findings first seen by Metasploit (no nmap title).
MSF_NSE_TITLES = {
    "smb-vuln-ms17-010": "Remote Code Execution vulnerability in Microsoft "
                         "SMBv1 servers (ms17-010)",
    "rmi-vuln-classloader": "RMI registry default configuration remote code "
                            "execution vulnerability",
    "ssl-heartbleed": "OpenSSL Heartbleed (CVE-2014-0160)",
    "ssl-ccs-injection": "SSL/TLS MITM vulnerability (CCS Injection)",
    "ipmi-cipher-zero": "IPMI 2.0 cipher zero authentication bypass",
}


def _version_text(rec):
    return " ".join(rec[k] for k in ("name", "product", "version", "extrainfo")
                    if rec[k])


def known_bad(records):
    """[(finding_id, [records])] for scan-level version/service matches."""
    hits = defaultdict(list)
    for rec in records:
        text = _version_text(rec)
        for pat, fid in VERSION_RULES:
            if re.search(pat, text, re.I):
                hits[fid].append(rec)
    return sorted(hits.items())


def _excerpt(text, start, end=None, after=0, limit=10):
    """The lines of text covering [start, end) plus `after` more lines —
    the evidence quoted for a finding."""
    end = start if end is None else end
    first = text.rfind("\n", 0, start) + 1
    stop = text.find("\n", max(end - 1, start))
    stop = len(text) if stop < 0 else stop
    for _ in range(after):
        nxt = text.find("\n", stop + 1)
        if nxt < 0:
            stop = len(text)
            break
        stop = nxt
    lines = text[first:stop].splitlines()
    return "\n".join(lines[:limit]).rstrip()


def _nse_vulns(text):
    """(script, title, excerpt) for every NSE block whose State is VULNERABLE
    — 'NOT VULNERABLE' is ignored."""
    out = []
    for m in re.finditer(r"^\|[_ ]\s?([\w.-]+):\s*\n((?:\|.*\n?)+?)(?=^\|[_ ]?\s?[\w.-]+:\s*\n|^[^|]|\Z)",
                         text, re.M):
        script, body = m.group(1), m.group(2)
        if not re.search(r"State:\s*(LIKELY\s+)?VULNERABLE", body):
            continue
        t = re.search(r"VULNERABLE:\s*\n\|\s+(.+)", body)
        out.append((script, (t.group(1).strip() if t else script),
                    _excerpt(text, m.start(), m.end())))
    return out


def _ssl_findings(text):
    """[(finding_id, detail, excerpt)] from ssl-enum-ciphers / ssl-cert /
    sslv2."""
    out = []
    old, lines = [], []
    for p in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
        m = re.search(rf"^\|\s+{re.escape(p)}:\s*$", text, re.M)
        if m:
            old.append(p)
            lines.append(_excerpt(text, m.start()))
    v2 = re.search(r"SSLv2 supported", text)
    if v2 and "SSLv2" not in old:
        old.insert(0, "SSLv2")
        lines.insert(0, _excerpt(text, v2.start()))
    if old:
        out.append(("tls-old-proto", ", ".join(old), "\n".join(lines)))
    grade = re.search(r"least strength:\s*([C-F])\b", text)
    if grade:
        out.append(("tls-weak-cipher", f"least strength {grade.group(1)}",
                    _excerpt(text, grade.start())))
    after = re.search(r"Not valid after:\s*(\d{4}-\d{2}-\d{2})", text)
    if after and after.group(1) < f"{_dt.date.today():%Y-%m-%d}":
        out.append(("tls-cert-expired", f"expired {after.group(1)}",
                    _excerpt(text, after.start())))
    subj = re.search(r"ssl-cert: Subject: (.+)", text)
    iss = re.search(r"\|\s+Issuer: (.+)", text)
    if subj and iss and subj.group(1).strip() == iss.group(1).strip():
        out.append(("tls-self-signed", subj.group(1).strip()[:80],
                    _excerpt(text, subj.start()) + "\n"
                    + _excerpt(text, iss.start())))
    return out


def _nfs_findings(text):
    """[(finding_id, detail, excerpt)] from showmount -e / nfs-showmount /
    nfs-ls."""
    out = []
    for m in re.finditer(r"(?:Export list for \S+:|nfs-showmount:)[ \t]*\n"
                         r"((?:(?:\|_?)?[ \t]*/.*\n?)+)", text):
        for line in m.group(1).splitlines():
            parts = line.lstrip("|_ \t").split()
            if parts and parts[0] == "/":
                out.append(("nfs-root-export", " ".join(parts),
                            _excerpt(text, m.start(), m.end())))
    for m in re.finditer(r"nfs-ls: Volume (\S+)[ \t]*\n\|\s+access: (.+)", text):
        if re.search(r"\b(Modify|Extend|Delete)\b", m.group(2)):
            out.append(("nfs-writable",
                        f"{m.group(1)} ({m.group(2).strip()})",
                        _excerpt(text, m.start(), m.end())))
    return out


def _smb_anon_shares(text):
    """(share, excerpt) for each share nmap smb-enum-shares reports with
    anonymous access."""
    shares, cur, cur_line = [], None, ""
    for line in text.splitlines():
        m = re.search(r"\\\\[^\\\s]+\\([^:\s]+):", line)
        if m:
            cur, cur_line = m.group(1), line
            continue
        a = re.search(r"Anonymous access:\s*(READ/WRITE|READ)", line)
        if a and cur and cur.upper() != "IPC$":  # IPC$ = null session finding
            shares.append((f"{cur} ({a.group(1)})", f"{cur_line}\n{line}"))
            cur = None
    return shares


# Output of the hand-run checklist commands (interactive sessions, client
# tools) -> finding id. Applied to evidence files only. profile None = any.
EVIDENCE_RULES = [
    (r"uid=\d+\([\w-]+\)", "bindshell", "bindshell"),
    (r"^230[ -]", "ftp-anon", "ftp"),
    (r"^\|?\s*root@\S+", "mysql-empty", "mysql"),
    (r"name of display:", "x11-open", "x11"),
    # openssl s_client: an ACCEPTED old handshake. Not "Protocol : TLSv1" —
    # openssl prints that even when the server refused (Cipher is (NONE)).
    (r"^New, (SSLv3|TLSv1(\.1)?), Cipher is (?!\(NONE\))\S+",
     "tls-old-proto", "ssl"),
    (r"^\s*Sharename\s+Type\s+Comment", "smb-null", "smb"),
]


def _nmap_port_lines(text, port):
    """'name product version' for nmap '<port>/<proto> open ...' lines."""
    for m in re.finditer(rf"^{port}/(?:tcp|udp)\s+open\s+(\S+)[ \t]*(.*)$",
                         text, re.M):
        yield f"{m.group(1)} {m.group(2)}".strip(), m.start()


def add_finding(found, fid, ip, port, proto, source, file, excerpt,
                detail="", fmt=None):
    """Record one sighting of a finding: merges sources and evidence into
    the entry for (ip, port, proto, detail)."""
    e = found[fid].setdefault((ip, port, proto, detail), {
        "ip": ip, "port": port, "proto": proto, "detail": detail,
        "fmt": {}, "sources": [], "evidence": []})
    for k, v in (fmt or {}).items():
        e["fmt"].setdefault(k, v)
    if source not in e["sources"]:
        e["sources"].append(source)
    ev = {"source": source, "file": file, "excerpt": excerpt}
    if ev not in e["evidence"]:
        e["evidence"].append(ev)


def analyze(records, jobs, found=None):
    """finding_id -> {(ip, port, proto, detail): entry}. Each entry holds
    the sources that saw it (Recon, Metasploit (auto|manual), Manual) and
    the evidence: [{source, file, excerpt}]. Combines scan-level rules with
    check-output parsing; jobs may carry their own `source` / `evidence`."""
    found = defaultdict(dict) if found is None else found

    def add(*a, **k):
        add_finding(found, *a, **k)

    for fid, recs in known_bad(records):
        for r in recs:
            line = (f"{r['port']}/{r['proto']}  open  {r['name']}  "
                    + " ".join(x for x in (r["product"], r["version"],
                                           r["extrainfo"]) if x))
            add(fid, r["ip"], r["port"], r["proto"], "Recon",
                "scan-tcp.nmap" if r["proto"] == "tcp" else "scan-udp.nmap",
                line, " ".join(x for x in (r["product"], r["version"]) if x),
                {"scheme": "https" if is_ssl(r) else "http"})
    for j in jobs:
        text = j.get("out") or ""
        if not text or j.get("status") != "ok":
            continue
        source = j.get("source", "Recon")
        ev = j.get("evidence") or f"service-checks/{j['group']}.txt"
        prof = j["prof"]
        ip, port, proto = j["ip"], j["port"], j["proto"]
        # The scheme that actually answered, for {scheme} in repro commands.
        sch = {"scheme": "https" if "https://" in j["cmd"] else "http"}
        for pat, fid in OUTPUT_RULES:
            if RULE_PROFILE.get(fid, prof) != prof:
                continue
            m = re.search(pat, text, re.M)
            if m:
                add(fid, ip, port, proto, source, ev,
                    _excerpt(text, m.start(), m.end(), after=1), "", sch)
        for share, exc in _smb_anon_shares(text):
            # The share name comes from the target: quote it, so a name
            # like $(cmd) can't run on the tester's machine when the
            # reproduce command is pasted.
            add("smb-share-anon", ip, port, proto, source, ev, exc, share,
                {"share": shlex.quote(share.split(" ")[0])})
        for script, title, exc in _nse_vulns(text):
            su = "-sU " if proto == "udp" else ""
            add(f"nse:{script}", ip, port, proto, source, ev, exc, "",
                {"cmd": f"nmap -Pn {su}-p{port} --script {script} {ip}",
                 "title": title})
        if prof == "ssl":
            for fid, detail, exc in _ssl_findings(text):
                add(fid, ip, port, proto, source, ev, exc, detail)
        if prof in ("nfs", "rpcbind"):
            for fid, detail, exc in _nfs_findings(text):
                add(fid, ip, port, proto, source, ev, exc, detail)
        if source != "Manual":
            continue
        # Hand-run evidence: client/interactive output and nmap -sV lines.
        for pat, fid, need in EVIDENCE_RULES:
            if need and need != prof:
                continue
            m = re.search(pat, text, re.M)
            if m:
                add(fid, ip, port, proto, source, ev,
                    _excerpt(text, m.start(), m.end(), after=1), "", sch)
        for vtext, pos in _nmap_port_lines(text, port):
            for pat, fid in VERSION_RULES:
                if re.search(pat, vtext, re.I):
                    add(fid, ip, port, proto, source, ev,
                        _excerpt(text, pos), "", sch)
    return found


def is_handled(rec):
    """True if some automated step (check, msf module, web shot) covers it."""
    for prof in profiles_for(rec):
        pb = PLAYBOOK.get(prof, {})
        if pb.get("checks") or pb.get("msf"):
            return True
    return False


# ---------------------------------------------------------------------------
# Per-service output files
# ---------------------------------------------------------------------------

def write_service_files(records, outdir):
    buckets = defaultdict(list)
    for r in records:
        buckets[bucket_for(r)].append(r)

    svc_dir = os.path.join(outdir, "open-ports")
    os.makedirs(svc_dir, exist_ok=True)
    for bucket, recs in sorted(buckets.items()):
        path = os.path.join(svc_dir, f"{bucket}-open.txt")
        with open(path, "w") as f:
            f.write(f"# {bucket.upper()} — {len(recs)} open port(s)\n")
            f.write(f"# generated {_dt.datetime.now():%Y-%m-%d %H:%M}\n\n")
            for r in sorted(recs, key=lambda x: (x["ip"], x["port"])):
                ver = " ".join(x for x in (r["product"], r["version"],
                                           r["extrainfo"]) if x)
                line = f"{r['ip']}:{r['port']}/{r['proto']}"
                if ver:
                    line += f"\t{ver}"
                f.write(line + "\n")
        log(f"wrote {path} ({len(recs)})", "+")

    with open(os.path.join(svc_dir, "all-open.txt"), "w") as f:
        for r in sorted(records, key=lambda x: (x["ip"], x["port"])):
            f.write(f"{r['ip']}:{r['port']}/{r['proto']}\t{bucket_for(r)}\t"
                    f"{r['name']}\n")
    return buckets


# ---------------------------------------------------------------------------
# Web screenshots
# ---------------------------------------------------------------------------

def build_web_urls(records):
    urls = []
    seen = set()
    for r in records:
        if r["proto"] != "tcp" or not is_web(r):
            continue
        for scheme in ("http", "https"):
            u = f"{scheme}://{r['ip']}:{r['port']}"
            if u not in seen:
                seen.add(u)
                urls.append(u)
    return urls


def pd_httpx():
    """Return ProjectDiscovery httpx binary name, or None.

    Kali ships it as httpx-toolkit; a plain `httpx` may be the unrelated
    Python HTTP client, so check before trusting it.
    """
    if which("httpx-toolkit"):
        return "httpx-toolkit"
    if which("httpx"):
        _, o, e = run(["httpx", "-version"], timeout=20)
        if "projectdiscovery" in (o + e).lower() or "Current Version" in o + e:
            return "httpx"
    return None


def screenshot(urls, outdir, manual):
    if not urls:
        log("no web URLs to screenshot", "-")
        return None
    shot_dir = os.path.join(outdir, "web-screenshots")
    os.makedirs(shot_dir, exist_ok=True)
    urlfile = os.path.join(shot_dir, "urls.txt")
    with open(urlfile, "w") as f:
        f.write("\n".join(urls) + "\n")

    httpx_bin = pd_httpx()
    if which("gowitness"):
        log(f"gowitness over {len(urls)} URLs")
        run(["gowitness", "scan", "file", "-f", urlfile,
             "--screenshot-path", shot_dir, "--write-db", "--write-db-uri",
             f"sqlite://{os.path.join(shot_dir, 'gowitness.sqlite3')}"],
            timeout=3600, capture=False)
    elif httpx_bin:
        log(f"{httpx_bin} screenshotting over {len(urls)} URLs")
        run([httpx_bin, "-l", urlfile, "-ss", "-srd", shot_dir, "-silent"],
            timeout=3600, capture=False)
    else:
        log("neither gowitness nor ProjectDiscovery httpx found — "
            "skipping screenshots", "!")

    report, n = build_html_report(shot_dir, urls, outdir)
    if n == 0:
        manual["auto"].append((
            "Web screenshots not captured",
            [f"{len(urls)} URL(s) in {urlfile} — open them in a browser, or "
             "install gowitness/httpx-toolkit and run:",
             f"`gowitness scan file -f {urlfile}`"]))
    return report


def _norm(x):
    return re.sub(r"[^0-9a-z]", "", x.lower())


def gowitness_meta(shot_dir):
    """url (no trailing /) -> {final, code, title, file} from gowitness's DB."""
    meta = {}
    db = os.path.join(shot_dir, "gowitness.sqlite3")
    if not os.path.exists(db):
        return meta
    try:
        con = sqlite3.connect(db)
        for url, final, code, title, fn, failed in con.execute(
                "select url, final_url, response_code, title, filename, "
                "failed from results order by id"):
            meta[(url or "").rstrip("/")] = {
                "final": final or "", "code": code, "title": title or "",
                "file": fn or "", "failed": bool(failed)}
        con.close()
    except sqlite3.Error:
        pass
    return meta


def build_html_report(shot_dir, urls, outdir):
    imgs = {}
    for root, _, files in os.walk(shot_dir):
        for fn in files:
            if fn.lower().endswith((".png", ".jpg", ".jpeg")):
                rel = os.path.relpath(os.path.join(root, fn), outdir)
                imgs[_norm(os.path.splitext(fn)[0])] = rel
    meta = gowitness_meta(shot_dir)

    cards, used = [], set()
    for u in urls:
        m = meta.get(u.rstrip("/"), {})
        key = _norm(os.path.splitext(m.get("file", ""))[0]) or _norm(u)
        img = imgs.get(key) or imgs.get(_norm(u))
        if img:
            used.add(img)
        cards.append((u, img, m))
    n_shots = sum(1 for _, img, _ in cards if img)
    cards.sort(key=lambda c: (c[1] is None, c[0]))  # answered first

    e = html.escape
    report = os.path.join(outdir, "web-report.html")
    now = f"{_dt.datetime.now():%Y-%m-%d %H:%M}"
    with open(report, "w") as f:
        f.write(f"""<!doctype html><html><head><meta charset="utf-8">
<title>Web Recon Report</title><style>
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:24px}}
h1{{color:#58a6ff;margin:0 0 4px}} h2{{font-size:16px;margin:28px 0 10px}}
a{{color:#58a6ff;text-decoration:none}} a:hover{{text-decoration:underline}}
.meta{{color:#8b949e;font-size:12px;margin-bottom:20px}}
table{{border-collapse:collapse;font-size:13px;width:100%;max-width:1100px}}
td,th{{text-align:left;padding:6px 10px;border-bottom:1px solid #30363d;vertical-align:top}}
th{{color:#8b949e}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:16px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}}
.card img{{width:100%;display:block;border-bottom:1px solid #30363d}}
.card .u{{padding:10px;font-size:13px;word-break:break-all}}
.card .t{{color:#8b949e;font-size:12px;margin-top:4px}}
.code{{display:inline-block;padding:1px 6px;border-radius:4px;font-size:11px;background:#30363d;margin-right:6px}}
.c2{{background:#1f6f3b}} .c3{{background:#6e5a12}} .c4{{background:#7d2a2a}} .c5{{background:#7d2a2a}}
.noshot{{padding:40px;text-align:center;color:#8b949e}}</style></head><body>
<h1>Web Recon Report</h1>
<div class="meta">{len(urls)} URLs probed (http+https) &middot; {n_shots} answered &middot; {now}</div>
<h2>All URLs probed</h2>
<table><tr><th>URL</th><th>Status</th><th>Title</th><th>Redirected to</th></tr>""")
        for u, img, m in cards:
            code = m.get("code") or ""
            status = e(str(code)) if code else ("" if img else "—")
            final = (f'<a href="{e(m["final"])}" target="_blank" '
                     f'rel="noopener">{e(m["final"])}</a>'
                     if m.get("final") and m["final"].rstrip("/") != u.rstrip("/")
                     else "")
            f.write(f'<tr><td><a href="{e(u)}" target="_blank" rel="noopener">'
                    f'{e(u)}</a></td><td>{status}</td>'
                    f'<td>{e(m.get("title", ""))}</td><td>{final}</td></tr>')
        f.write('</table><h2>Screenshots</h2><div class="grid">')
        for u, img, m in cards:
            code = m.get("code")
            badge = (f'<span class="code c{str(code)[0]}">{code}</span>'
                     if code else "")
            link = f'<a href="{e(u)}" target="_blank" rel="noopener">{e(u)}</a>'
            if img:
                body = (f'<a href="{e(u)}" target="_blank" rel="noopener">'
                        f'<img src="{e(img)}" loading="lazy" alt="{e(u)}"></a>')
            else:
                body = '<div class="noshot">no response / no screenshot</div>'
            title = (f'<div class="t">{e(m["title"])}</div>'
                     if m.get("title") else "")
            f.write(f'<div class="card">{body}<div class="u">{badge}{link}'
                    f'{title}</div></div>')
        for img in sorted(set(imgs.values()) - used):  # stray shots, no URL
            f.write(f'<div class="card"><a href="{e(img)}" target="_blank">'
                    f'<img src="{e(img)}" loading="lazy"></a><div class="u">'
                    f'{e(os.path.basename(img))}</div></div>')
        f.write("</div></body></html>")
    log(f"wrote {report} ({n_shots} screenshots, {len(urls)} links)", "+")
    return report, n_shots


# ---------------------------------------------------------------------------
# Automated per-port checks (safe enumeration only)
# ---------------------------------------------------------------------------

def expand(tmpl, rec, prof):
    """Fill a playbook template for one record. Returns a list of commands
    (web templates with {scheme} yield both http and https)."""
    ssl = is_ssl(rec)
    if "{scheme}" not in tmpl:
        schemes = ("",)
    elif prof == "web":
        schemes = ("http", "https")
    else:
        schemes = ("https",) if ssl else ("http",)
    starttls = "" if rec["tunnel"] == "ssl" else STARTTLS.get(svc_name(rec), "")
    return [" ".join(tmpl.format(
                ip=rec["ip"], port=rec["port"], scheme=s,
                sU="-sU" if rec["proto"] == "udp" else "",
                ldap="ldaps" if ssl else "ldap", starttls=starttls).split())
            for s in schemes]


def plan_checks(records):
    """Expand the playbook into concrete jobs, one per (host, command)."""
    jobs, seen = [], set()
    for r in sorted(records, key=lambda x: (x["port"], x["ip"])):
        for prof in profiles_for(r):
            for tool, tmpl in PLAYBOOK.get(prof, {}).get("checks", []):
                for cmd in expand(tmpl, r, prof):
                    # Dedup host-level commands (e.g. enum4linux-ng on 139+445).
                    if (r["ip"], cmd) in seen:
                        continue
                    seen.add((r["ip"], cmd))
                    jobs.append({
                        "group": f"port-{r['port']}-{r['proto']}-{prof}",
                        "ip": r["ip"], "port": r["port"],
                        "proto": r["proto"], "prof": prof,
                        "tool": tool, "cmd": cmd,
                        "variant": (r["ip"], r["port"], prof, tmpl),
                    })
    return jobs


def plan_risky(records):
    """One entry per (host:port, risky playbook) — {fid, ip, port, proto,
    prof, cmds}. Never run."""
    out, seen = [], set()
    for r in sorted(records, key=lambda x: (x["port"], x["ip"])):
        for prof in profiles_for(r):
            pb = PLAYBOOK.get(prof, {})
            if not pb.get("risky"):
                continue
            key = (r["ip"], r["port"], r["proto"], prof)
            if key in seen:
                continue
            seen.add(key)
            by_fid = defaultdict(list)
            for item in pb["risky"]:
                fid = item[2] if len(item) > 2 else pb["risky_finding"]
                by_fid[fid] += expand(item[1], r, prof)
            for fid, cmds in by_fid.items():
                out.append({"fid": fid, "ip": r["ip"], "port": r["port"],
                            "proto": r["proto"], "prof": prof, "cmds": cmds})
    return out


def plan_logins(records):
    """{(service, port, proto): [ips]} for every port with a login module.
    Never run — listed so nobody assumes credentials were tested."""
    out = defaultdict(set)
    for r in records:
        for prof in profiles_for(r):
            # r-services have no rc login block (rsh takes no password) but
            # are login/trust tests all the same.
            if (PLAYBOOK.get(prof, {}).get("login")
                    or prof in ("rexec", "rlogin", "rsh")):
                out[(prof, r["port"], r["proto"])].add(r["ip"])
    return {k: sorted(v, key=lambda ip: tuple(int(x) if x.isdigit() else 0
                                              for x in ip.split(".")))
            for k, v in sorted(out.items(), key=lambda kv: kv[0][1])}


LOGIN_TITLE = "Credential testing NOT done"


def login_item(records):
    """The Manual follow-up item for untested login services, or None."""
    logins = plan_logins(records)
    if not logins:
        return None
    return (f"{LOGIN_TITLE} — {len(logins)} login service(s), never tested "
            "automatically",
            [f"{svc} {port}/{proto}: {', '.join(ips)}"
             for (svc, port, proto), ips in logins.items()]
            + ["Run by hand only if credential testing is in scope (it can "
               "lock accounts): docs/workflow/MANDATORY_CHECKS.md → Credential "
               "testing. Commented out in metasploit.rc."])


def _exec_job(job, timeout):
    if not which(job["tool"]):
        job.update(status="missing", out="", err="")
        return job
    argv = shlex.split(job["cmd"])
    if "-sU" in argv and not is_root():
        job.update(status="needs-root", out="", err="")
        return job
    rc, out, err = run(argv, timeout=timeout)
    if rc == 124 and err == "timeout":
        status = "timeout"
    elif not out.strip():
        status = "failed"
    elif (job["tool"] == "nmap" and "--script" in argv
          and not re.search(r"^\|", out, re.M)):
        # nmap always prints a header; no `|` lines = no script said anything.
        status = "no-result"
    else:
        status = "ok"
    job.update(status=status, rc=rc, out=out, err=err)
    return job


def run_checks(records, outdir, threads, timeout, manual):
    jobs = plan_checks(records)
    chk_dir = os.path.join(outdir, "service-checks")
    os.makedirs(chk_dir, exist_ok=True)
    if not jobs:
        log("no automated checks apply", "-")
        return []

    log(f"running {len(jobs)} automated checks ({threads} parallel)")
    done = 0
    ex = ThreadPoolExecutor(max_workers=threads)
    futs = [ex.submit(_exec_job, j, timeout) for j in jobs]
    try:
        for fut in as_completed(futs):
            j = fut.result()
            done += 1
            lvl = "+" if j["status"] == "ok" else "-"
            log(f"({done}/{len(jobs)}) {j['status']:<7} {j['ip']}:{j['port']}"
                f" {j['tool']}", lvl)
    except KeyboardInterrupt:
        # Stop ALL target traffic: drop the queued checks first, then kill
        # the running ones (a plain `with` would wait for the whole queue).
        for f in futs:
            f.cancel()
        kill_running()
        ex.shutdown(wait=False)
        raise
    ex.shutdown()

    # http vs https probes of one port: only one scheme is expected to answer,
    # so a failed scheme whose sibling worked is not a manual-check item.
    answered = {j["variant"] for j in jobs if j["status"] == "ok"}
    for j in jobs:
        if j["status"] == "failed" and j["variant"] in answered:
            j["status"] = "no-answer"

    by_group = defaultdict(list)
    for j in jobs:
        by_group[j["group"]].append(j)

    sh = ["#!/bin/sh", "# reconflow — every automated check, re-runnable by hand.",
          "# Lines marked SKIPPED/TIMEOUT/FAILED need manual attention.", ""]
    for group, gjobs in sorted(by_group.items(),
                               key=lambda kv: (kv[1][0]["port"], kv[0])):
        path = os.path.join(chk_dir, f"{group}.txt")
        with open(path, "w") as f:
            f.write(f"# {group} — {len({j['ip'] for j in gjobs})} host(s)\n")
            for ip in sorted({j["ip"] for j in gjobs}):
                f.write(f"\n===== {ip} =====\n")
                for j in (x for x in gjobs if x["ip"] == ip):
                    f.write(f"\n### [{j['status']}] $ {j['cmd']}\n")
                    if j["status"] == "missing":
                        f.write(f"({j['tool']} not installed — skipped)\n")
                    elif j["status"] == "needs-root":
                        f.write("(UDP scan needs root — skipped)\n")
                    else:
                        f.write(j["out"] or j["err"] or "(no output)\n")
        sh.append(f"# ---- {group} ----")
        for j in gjobs:
            tag = {"missing": f"SKIPPED ({j['tool']} not installed)",
                   "needs-root": "SKIPPED (needs root)",
                   "timeout": "TIMEOUT", "failed": "FAILED"}.get(j["status"])
            if j["status"] == "no-result":
                sh.append("# NO RESULT (no nmap script output):")
            sh.append(f"# {tag}: {j['cmd']}" if tag else j["cmd"])
        sh.append("")
    risky = [c for e in plan_risky(records) for c in e["cmds"]]
    if risky:
        sh += ["# ---- RISKY — never run automatically; run by hand only if in "
               "scope ----",
               "# (login attempts / relay tests / username guessing / proxy "
               "fetches / remote class loading — see "
               "docs/workflow/MANDATORY_CHECKS.md)"]
        sh += [f"# {c}" for c in risky] + [""]
    with open(os.path.join(chk_dir, "commands.sh"), "w") as f:
        f.write("\n".join(sh) + "\n")

    # Anything automation couldn't do goes to 'Manual follow-up'.
    missing = defaultdict(list)
    for j in jobs:
        if j["status"] == "missing":
            missing[j["tool"]].append(j["cmd"])
    for tool, cmds in sorted(missing.items()):
        manual["auto"].append((f"`{tool}` not installed — {len(cmds)} "
                               "check(s) skipped",
                               [f"`{c}`" for c in cmds]))
    noroot = [j for j in jobs if j["status"] == "needs-root"]
    if noroot:
        manual["auto"].append((f"{len(noroot)} UDP check(s) skipped — need root",
                               [f"`sudo {j['cmd']}`" for j in noroot]))
    empty = [j for j in jobs if j["status"] == "no-result"]
    if empty:
        manual["auto"].append((
            f"{len(empty)} nmap check(s) gave no script output — usually "
            "means not vulnerable / not applicable",
            [f"`{j['cmd']}`" for j in empty]))
    for status in ("timeout", "failed"):
        bad = [j for j in jobs if j["status"] == status]
        if bad:
            manual["auto"].append((
                f"{len(bad)} check(s) {'timed out' if status == 'timeout' else 'returned nothing / errored'}"
                " — re-run by hand",
                [f"`{j['cmd']}`" + (f"  ({j['err'].strip()[:80]})"
                                    if status == "failed" and j["err"].strip()
                                    else "")
                 for j in bad]))
    ok = sum(j["status"] == "ok" for j in jobs)
    log(f"automated checks: {ok}/{len(jobs)} ok — output in {chk_dir}/", "+")
    return jobs


# ---------------------------------------------------------------------------
# Needs-attention: services with no automation at all
# ---------------------------------------------------------------------------

def write_needs_attention(records, outdir, manual):
    """Per-port files for services with NO automated coverage, for manual review."""
    na = [r for r in records if not is_handled(r)]
    if not na:
        log("needs-attention: none — every service had automated coverage", "+")
        return
    na_dir = os.path.join(outdir, "needs-attention")
    os.makedirs(na_dir, exist_ok=True)

    by_port = defaultdict(list)
    for r in na:
        by_port[(r["port"], r["proto"])].append(r)

    summary = []
    for (port, proto), recs in sorted(by_port.items()):
        name = (svc_name(recs[0]).replace("/", "-") or "unknown")
        fn = f"port-{port}-{proto}-{name}.txt"
        path = os.path.join(na_dir, fn)
        with open(path, "w") as f:
            f.write(f"# NEEDS MANUAL ATTENTION — {port}/{proto} ({name})\n")
            f.write("# No automated module/check was run for this service.\n")
            f.write(f"# {len(recs)} host(s). Review the nmap detail and test "
                    "by hand.\n\n")
            for r in sorted(recs, key=lambda x: x["ip"]):
                ver = " ".join(x for x in (r["product"], r["version"],
                                           r["extrainfo"]) if x)
                line = f"{r['ip']}:{r['port']}/{r['proto']}\t{r['name']}"
                if ver:
                    line += f"\t{ver}"
                f.write(line + "\n")
        summary.append(f"{port}/{proto} ({name}): {len(recs)} host(s)  -> {fn}")
        ips = sorted({r["ip"] for r in recs})
        ver = " ".join(x for x in (recs[0]["product"], recs[0]["version"]) if x)
        detail = [f"Hosts: {', '.join(ips)}", f"Detail: needs-attention/{fn}"]
        detail += [f"Hint: {s}" for s in PLAYBOOK.get(bucket_for(recs[0]), {})
                   .get("manual", [])]
        manual["none"].append((f"{port}/{proto} {name}"
                               + (f" ({ver})" if ver else ""), detail))
        log(f"wrote {path} ({len(recs)})", "-")

    with open(os.path.join(na_dir, "SUMMARY.txt"), "w") as f:
        f.write("# Services with NO automated coverage — review these manually.\n")
        f.write(f"# generated {_dt.datetime.now():%Y-%m-%d %H:%M}\n\n")
        f.write("\n".join(summary) + "\n")
    log(f"needs-attention: {len(by_port)} port(s) flagged for manual review", "-")


# ---------------------------------------------------------------------------
# Metasploit: workspace + db_import + port-by-port module runs.
# Modules pull RHOSTS from the DB via `services -p <port> -R`.
# ---------------------------------------------------------------------------

def _ws_name(outdir):
    """A new msf workspace per run: <folder>_<YYYYmmdd_HHMMSS>. A re-run
    into the same folder never inherits hosts an earlier run imported."""
    base = os.path.basename(os.path.abspath(outdir)) or "reconflow"
    base = re.sub(r"[^A-Za-z0-9_]", "_", base)
    return f"{base}_{_dt.datetime.now():%Y%m%d_%H%M%S}"


def write_msf_rc(records, xml_paths, outdir, drop_ips=(), ws=None):
    """Emit a DB-driven resource file: workspace -> db_import -> run per port.
    drop_ips (out-of-scope hosts present in the XML) are deleted from the
    workspace right after the import so no module ever targets them."""
    path = os.path.join(outdir, "metasploit.rc")
    ws = ws or _ws_name(outdir)
    abs_out = os.path.abspath(outdir)
    spool = os.path.join(abs_out, "msf-run.log")

    # (port, proto, profile) -> hosts / nmap names / ssl
    groups = defaultdict(lambda: {"ips": set(), "names": set(), "ssl": False})
    for r in records:
        for prof in profiles_for(r):
            pb = PLAYBOOK.get(prof, {})
            if not pb.get("msf") and not pb.get("login"):
                continue
            g = groups[(r["port"], r["proto"], prof)]
            g["ips"].add(r["ip"])
            g["names"].add(svc_name(r))
            g["ssl"] |= is_ssl(r)

    # A port carrying different services on different hosts gets a `-s name`
    # filter so each module only targets the hosts running its service.
    namesets = defaultdict(set)
    for (port, _, _), g in groups.items():
        namesets[port].add(frozenset(g["names"]))
    # `services` can't filter by protocol, so a port open over both TCP and
    # UDP gets its exact host list instead of `services -p N -R`.
    protos = defaultdict(set)
    for r in records:
        protos[r["port"]].add(r["proto"])

    L = []
    L.append("# ============================================================")
    L.append("# reconflow — Metasploit resource file (DB-driven)")
    L.append("# Run:  msfconsole -r metasploit.rc")
    L.append("# Needs msf database up:  msfdb init   (or: sudo msfdb run)")
    L.append("# RHOSTS for each module come straight from the imported scan")
    L.append("# via `services -p <port> -R`.  AUTHORIZED TARGETS ONLY.")
    L.append("# ============================================================")
    L.append("")
    # msfconsole splits rc lines like a POSIX shell, so shlex.quote keeps
    # paths with spaces intact.
    L.append(f"spool {shlex.quote(spool)}")
    L.append(f"workspace -a {ws}")
    L.append(f"workspace {ws}")
    for x in xml_paths:
        L.append(f"db_import {shlex.quote(os.path.abspath(x))}")
    # msfconsole keeps a trailing `# …` as part of the arguments, so
    # comments go on their own line.
    if drop_ips:
        L.append("# out of scope — removed after the import:")
    for ip in sorted(drop_ips):
        L.append(f"hosts -d {ip}")
    L.append("hosts")
    L.append("services")
    L.append("setg THREADS 10")
    L.append("")

    for (port, proto, prof) in sorted(groups):
        g = groups[(port, proto, prof)]
        pb = PLAYBOOK[prof]
        if len(protos[port]) > 1:
            svc_q = "set RHOSTS " + " ".join(sorted(g["ips"]))
        else:
            svc_q = f"services -u -p {port}"
            names = sorted(n for n in g["names"] if n)
            if len(namesets[port]) > 1 and names:
                svc_q += f" -s {','.join(names)}"
            svc_q += " -R"
        L.append(f"# ---- {prof.upper()} on port {port}/{proto} "
                 f"({len(g['ips'])} host(s)) ----")
        for m in pb.get("msf", []):
            L.append(f"use {m}")
            L.append(svc_q)
            L.append(f"set RPORT {port}")
            if g["ssl"] and prof in SSL_AWARE:
                L.append("set SSL true")
            L.append("run")
            L.append("back")
        if pb.get("login"):
            L.append("# credential check (ENABLE DELIBERATELY — edit creds):")
            L.append(f"#   use {pb['login']}")
            L.append(f"#   {svc_q}")
            L.append(f"#   set RPORT {port}")
            L.append(f"#   set USER_FILE {USER_FILE}")
            L.append(f"#   set PASS_FILE {PASS_FILE}")
            L.append("#   run")
            L.append("#   back")
        L.append("")

    L.append("spool off")
    L.append("# exit   # uncomment to make the run exit msfconsole when done")
    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")
    log(f"wrote {path} (workspace '{ws}', {len(groups)} port/service blocks)",
        "+")
    return path


def write_msf_manual_rc(xml_paths, outdir, drop_ips=(), ws=None):
    """Emit msf-manual.rc: the setup for a hand-driven msfconsole session.
    Only spool + workspace + import — no module runs; the console stays
    open for you. The spool path is absolute, so the log lands in the
    output folder wherever msfconsole was started."""
    path = os.path.join(outdir, "msf-manual.rc")
    abs_out = os.path.abspath(outdir)
    ws = ws or _ws_name(outdir)
    L = ["# ============================================================",
         "# reconflow — setup for your own msfconsole session",
         f"# Run:  msfconsole -r {shlex.quote(os.path.abspath(path))}",
         "# Records the session to msf-manual.log for report.py, then",
         "# leaves you at the msf prompt. Runs no modules.",
         "# ============================================================",
         "",
         f"spool {shlex.quote(os.path.join(abs_out, 'msf-manual.log'))}",
         f"workspace -a {ws}",
         f"workspace {ws}"]
    L += [f"db_import {shlex.quote(os.path.abspath(x))}" for x in xml_paths]
    if drop_ips:
        L.append("# out of scope — removed after the import:")
    L += [f"hosts -d {ip}" for ip in sorted(drop_ips)]
    L += ["setg THREADS 10",
          f"cd {shlex.quote(abs_out)}"]
    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")
    return path


def msf_db_ready():
    _, out, _ = run(["msfconsole", "-q", "-x", "db_status; exit"],
                    timeout=300)
    return "connected to" in out.lower()


def run_msf(rc_path, outdir, manual):
    """Launch msfconsole against the generated rc and run to completion."""
    later = f"`cd {shlex.quote(outdir)} && msfconsole -r metasploit.rc`"
    if not which("msfconsole"):
        log("msfconsole not found — skipping auto-run (see "
            "docs/workflow/TOOLS_INSTALLATION.md)", "!")
        manual["auto"].append(("Metasploit not run (msfconsole not installed)",
                               ["Install metasploit-framework, then " + later]))
        return False
    log("checking msf database (db_status)...")
    if not msf_db_ready():
        log("msf database not connected — skipping auto-run", "!")
        manual["auto"].append(("Metasploit not run (database not connected)",
                               ["`sudo msfdb init` (or `sudo msfdb run`), "
                                "then " + later]))
        return False
    # A fresh log per run: spool appends, and the report must only show
    # this run's results.
    try:
        os.remove(os.path.join(outdir, "msf-run.log"))
    except OSError:
        pass
    # Run a copy that exits at the end so the console returns.
    tmp = rc_path + ".autorun"
    with open(rc_path) as fi, open(tmp, "w") as fo:
        fo.write(fi.read())
        fo.write("exit\n")
    log(f"launching: msfconsole -q -r {tmp}")
    run(["msfconsole", "-q", "-r", tmp], timeout=86400, capture=False)
    try:
        os.remove(tmp)
    except OSError:
        pass
    log("msfconsole run finished (see msf-run.log)", "+")
    return True


def parse_msf_log(outdir, manual):
    """Pull [+] hits and load failures back out of the spooled msf log."""
    path = os.path.join(outdir, "msf-run.log")
    if not os.path.exists(path):
        return []
    hits, failed = [], set()
    with open(path, errors="replace") as f:
        for line in f:
            s = re.sub(r"\x1b\[[0-9;]*m", "", line).rstrip()
            if "[+]" in s:
                hits.append(s)
            m = re.search(r"Failed to load module: (\S+)", s)
            if m:
                failed.add(m.group(1))
    with open(os.path.join(outdir, "msf-findings.txt"), "w") as f:
        f.write(f"# [+] lines from msf-run.log ({len(hits)})\n\n")
        f.write("\n".join(hits) + "\n")
    if failed:
        manual["auto"].append(("Metasploit module(s) failed to load",
                               [f"`{m}` — check the name with `search` / "
                                "update msf" for m in sorted(failed)]))
    log(f"msf: {len(hits)} [+] line(s) -> msf-findings.txt", "+")
    return hits


# ---------------------------------------------------------------------------
# Target lists + results.json (the report itself is built by report.py)
# ---------------------------------------------------------------------------

def write_results(outdir, **data):
    """results.json — everything report.py needs, so the report can be
    rebuilt at any time without touching a target."""
    keep = ("group", "ip", "port", "proto", "prof", "tool", "cmd", "status",
            "out", "err")
    data["jobs"] = [{k: j.get(k) for k in keep} for j in data["jobs"]]
    data.update(version=1, generated=f"{_dt.datetime.now():%Y-%m-%d %H:%M}")
    path = os.path.join(outdir, "results.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=1)
    return path


def write_target_files(records, outdir):
    """targets/port-<n>-<proto>-<profile>.txt — one IP per line, so msfconsole
    can load them with `set RHOSTS file:...` (works even with the DB down) and
    shell loops can do `for T in $(cat ...)`."""
    groups = defaultdict(set)
    for r in records:
        for prof in profiles_for(r):
            groups[(r["port"], r["proto"], prof)].add(r["ip"])
    tdir = os.path.join(outdir, "targets")
    os.makedirs(tdir, exist_ok=True)
    out = {}
    for (port, proto, prof), ips in sorted(groups.items()):
        path = os.path.abspath(os.path.join(
            tdir, f"port-{port}-{proto}-{prof}.txt"))
        with open(path, "w") as f:
            f.write("\n".join(sorted(ips)) + "\n")
        out[(port, proto, prof)] = (path, sorted(ips))
    log(f"wrote {len(out)} target list(s) to {tdir}/", "+")
    return out


# Everything a run regenerates. Cleared when re-running into a folder, so
# nothing from the earlier run (a service that has since closed, an old
# check) looks like this run's result. Your work is never in this list:
# manual-checklist.md, evidence/, msf-manual*.log, report-ids.json.
GENERATED_DIRS = ("open-ports", "targets", "needs-attention", "service-checks",
                  "web-screenshots")
GENERATED_FILES = ("web-report.html", "msf-findings.txt", "metasploit.rc",
                   "SAFE-CHECKS.md",
                   "msf-manual.rc", "scope-inscope.txt", "scope-excluded.txt")
SCAN_FILES = ("scan-tcp", "scan-tcp-ports", "scan-udp")


def clear_generated(outdir, from_xml, msf_now):
    """Remove the earlier run's generated output from outdir (see
    GENERATED_DIRS). Scan files go only when this run rescans (never with
    --from-xml — the XML may live here). An earlier automatic msf-run.log is
    renamed, not deleted, when Metasploit won't run now: report.py would
    otherwise show it as this run's result."""
    for d in GENERATED_DIRS:
        shutil.rmtree(os.path.join(outdir, d), ignore_errors=True)
    names = list(GENERATED_FILES)
    if not from_xml:
        names += [f"{p}.{ext}" for p in SCAN_FILES
                  for ext in ("nmap", "xml", "gnmap")]
        names.append("scan-tcp-hosts.txt")
    for n in names:
        try:
            os.remove(os.path.join(outdir, n))
        except OSError:
            pass
    old = os.path.join(outdir, "msf-run.log")
    if os.path.exists(old) and not msf_now:
        stamp = _dt.datetime.fromtimestamp(os.path.getmtime(old))
        new = os.path.join(outdir, f"msf-run-previous-{stamp:%Y%m%d_%H%M%S}"
                                   ".log")
        os.rename(old, new)
        log(f"earlier automatic Metasploit log kept as {new} (not part of "
            "this run's report)", "-")


def run_safe_checks(args, manual):
    """The safe manual checks (safechecks.py, MANDATORY_CHECKS Part 1) on
    every target. Their output lands in evidence/, which report.py reads;
    what needs your judgement shows up in FINDINGS.md as possible issues."""
    sys.modules.setdefault("reconflow", sys.modules[__name__])
    import safechecks
    plan, skipped = safechecks.make_plan(args.outdir, args.domain,
                                         args.with_data, args.testssl)
    n = sum(len(p) for _, p in plan)
    log(f"safe checks: {n} run(s) of {len(plan)} check(s) "
        f"({len(skipped)} skipped)")
    safechecks.execute(args.outdir, plan, skipped, args.domain, args.threads)
    if skipped:
        here = os.path.dirname(os.path.abspath(__file__))
        manual["auto"].append((
            f"{len(skipped)} safe check(s) skipped — see SAFE-CHECKS.md",
            [f"`{c['name']}` ({c['what']}, {k} host:port): {why}"
             for c, k, why in skipped]
            + ["Re-run just those later (never touches anything else): "
               f"`sudo python3 {shlex.quote(os.path.join(here, 'safechecks.py'))} "
               f"{shlex.quote(os.path.abspath(args.outdir))} --only "
               f"{','.join(c['name'] for c, _, _ in skipped)}` + the flag "
               "named above"]))


def ask_yes(prompt):
    """y/yes -> True. Anything else, or no terminal to answer, -> False."""
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        print()
        return False


def print_manual_banner(manual, report):
    todo = manual["auto"] + manual["none"]
    print()
    if not todo:
        log(f"everything automatable ran — see {report}", "+")
        return
    bar = "=" * 70
    print(f"\033[93m{bar}\n  MANUAL CHECK REQUIRED — the automation could not "
          f"cover {len(todo)} item(s)\n{bar}\033[0m")
    for title, lines in manual["auto"]:
        print(f"  [ ] {title}")
        for ln in lines[:3]:
            print(f"        {ln}")
        if len(lines) > 3:
            print(f"        ... +{len(lines) - 3} more")
    for title, lines in manual["none"]:
        print(f"  [ ] no automation: {title}")
        print(f"        {lines[0]}")
    print(f"\n  Details in {report} → 'Manual follow-up'")
    print("  Everything automation doesn't do (manual checks, then risky / "
          "credentials /\n  exploits): docs/workflow/MANDATORY_CHECKS.md\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="ReconFlow — authorized network recon orchestrator (scan → per-port checks → Metasploit → FINDINGS.md).")
    ap.add_argument("-o", "--outdir", required=True, metavar="DIR",
                    help="output folder for this run (required); created if "
                         "it doesn't exist")
    ap.add_argument("-iL", "--ips", default=None, metavar="FILE",
                    help="in-scope targets, one per line "
                         "(CIDR/range/IP). Default: scope/inscope_ips.txt")
    ap.add_argument("-x", "--exclude-file", default=None, metavar="FILE",
                    help="out-of-scope targets — never scanned or tested. "
                         "Use IPs/CIDRs/ranges, not hostnames (a hostname is "
                         "only excluded at its first resolved IP). "
                         "Default: scope/outofscope_ips.txt (if present)")
    ap.add_argument("targets", nargs="*",
                    help="targets on the command line (used instead of "
                         "the in-scope file)")
    ap.add_argument("--quick", action="store_true",
                    help="scan only the top 1000 TCP ports instead of all "
                         "65535 (default: all)")
    ap.add_argument("--no-udp", action="store_true",
                    help="skip the UDP scan (default: top --top-udp ports)")
    ap.add_argument("--top-udp", type=int, default=100, metavar="N",
                    help="number of top UDP ports to scan (default 100)")
    ap.add_argument("--timing", default="T4", help="nmap timing (T0-T5)")
    ap.add_argument("--extra", default="",
                    help="extra nmap args (quoted), added to the TCP and UDP "
                         "scans; a port spec here overrides the default ports "
                         "and --top-udp (use -p T:...,U:... to set each)")
    ap.add_argument("--pn", action="store_true",
                    help="skip host discovery (nmap -Pn): scan every address "
                         "even if it doesn't answer ping. Slower on sparse "
                         "ranges; use it when hosts block ping")
    ap.add_argument("--no-screens", action="store_true")
    ap.add_argument("--no-checks", action="store_true",
                    help="skip automated per-port checks")
    ap.add_argument("--no-safe-checks", action="store_true",
                    help="skip the safe manual checks (safechecks.py) that "
                         "run after the per-port checks")
    ap.add_argument("--domain", action="append", default=[], metavar="NAME",
                    help="domain for the safe DNS zone-transfer check "
                         "(repeat for several)")
    ap.add_argument("--with-data", action="store_true",
                    help="safe checks: also read sample documents from open "
                         "CouchDB / Elasticsearch (real data — only if in "
                         "scope)")
    ap.add_argument("--testssl", action="store_true",
                    help="safe checks: also run a full testssl.sh audit per "
                         "TLS port (slow)")
    ap.add_argument("--msf", action="store_true",
                    help="run the Metasploit modules automatically without "
                         "asking (default: ask; with -y alone: don't run)")
    ap.add_argument("--threads", type=int, default=8,
                    help="parallel automated checks (default 8)")
    ap.add_argument("--check-timeout", type=int, default=300,
                    help="seconds per automated check (default 300)")
    ap.add_argument("--from-xml", nargs="+", metavar="XML",
                    help="skip scanning, parse existing nmap XML instead; "
                         "hosts outside the in-scope list (if there is one) "
                         "and out-of-scope hosts are ignored")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="answer yes to 'Proceed with recon?' without asking "
                         "(for scripted runs); add --msf to run Metasploit too")
    args = ap.parse_args()
    for d in args.domain:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", d):
            ap.error(f"--domain {d!r}: letters, digits, dots and dashes only")

    # Default scope files are created on first use; with no targets in them
    # yet, stop before anything else (no empty output folder left behind).
    if not args.exclude_file:
        args.exclude_file = ensure_scope_file("outofscope_ips.txt")
    if not args.ips and not args.targets and not args.from_xml:
        args.ips = ensure_scope_file("inscope_ips.txt")
        if not read_target_list(args.ips):
            log(f"no targets yet: add them to {args.ips} (syntax: "
                "scope/ips.example.md), then run the same command again", "!")
            sys.exit(1)

    if os.path.exists(args.outdir) and not os.path.isdir(args.outdir):
        ap.error(f"output folder '{args.outdir}' exists but is a file")
    manual = {"auto": [], "none": []}

    # Out-of-scope list (the default was created above if missing).
    exclude_src = args.exclude_file
    if not os.path.exists(exclude_src):
        ap.error(f"exclude file '{exclude_src}' not found")
    excluded = read_target_list(exclude_src)
    in_excluded = scope_matcher(excluded)
    named = [e for e in excluded if is_hostname(e)]
    if named:
        log(f"hostname(s) in {exclude_src}: {', '.join(named)} — only the first "
            "IP each resolves to is excluded, and reverse DNS may not match. "
            "List their IPs instead (README → Scope files).", "!")

    inscope = []
    if args.from_xml:
        # No scan, but the XML may hold more hosts than this engagement's
        # scope: keep only the in-scope ones when an in-scope list exists.
        default_in = os.path.join(SCOPE_DIR, "inscope_ips.txt")
        if args.targets:
            inscope = list(args.targets)
        elif args.ips:
            if not os.path.exists(args.ips):
                ap.error(f"in-scope file '{args.ips}' not found")
            inscope = read_target_list(args.ips)
        elif os.path.exists(default_in):
            args.ips = _rel(default_in)
            inscope = read_target_list(default_in)
        if not inscope:
            log("no in-scope list to check the XML against — every host in it "
                "is processed (out-of-scope hosts are still dropped)", "!")
            manual["auto"].append((
                "Scan data was not checked against an in-scope list",
                ["--from-xml ran with no in-scope entries: every host in the "
                 "XML (minus out-of-scope ones) was processed. Check the hosts "
                 "in FINDINGS.md are all yours."]))
    else:
        if args.targets:
            inscope = list(args.targets)
        elif os.path.exists(args.ips):
            inscope = read_target_list(args.ips)
        else:
            ap.error(f"no targets: '{args.ips}' not found and none on cmdline")
        if not inscope:
            ap.error(f"no targets: '{args.ips}' has no entries")
        if not which("nmap"):
            log("nmap not found — install it first (docs/workflow/TOOLS_INSTALLATION.md)", "!")
            sys.exit(1)

    # Both decisions are made up front, before anything touches a target, so
    # the run is unattended afterwards.
    print("\n  AUTHORIZED USE ONLY. Scan only systems you have written "
          "permission to test.")
    if args.from_xml:
        print(f"  Scan data: {', '.join(args.from_xml)}")
        if inscope:
            src = "command line" if args.targets else args.ips
            print(f"  In scope ({src}): {len(inscope)} entries — hosts in the "
                  "XML outside it are ignored")
    else:
        src = "command line" if args.targets else args.ips
        print(f"  In scope ({src}): {len(inscope)} entries")
        print("   " + ", ".join(inscope[:8]) + (" ..." if len(inscope) > 8
                                                else ""))
    print(f"  Out of scope ({exclude_src if excluded else 'none'}): "
          f"{len(excluded)} entries — never touched")
    if excluded:
        print("   " + ", ".join(excluded[:8]) + (" ..." if len(excluded) > 8
                                                else ""))
    if not args.from_xml:
        tcp = "top 1000 TCP ports" if args.quick else "all 65535 TCP ports"
        udp = ("no UDP" if args.no_udp
               else f"top {args.top_udp} UDP ports" + ("" if is_root()
                                                      else " (needs root — "
                                                      "will be skipped)"))
        print(f"  Scan: {tcp} + {udp}"
              + (" — every address, no ping (--pn)" if args.pn else "")
              + ("" if args.quick and args.no_udp
                 else " — this can take a while"))
    print("\n  Recon runs the scan, the safe per-port checks and the safe "
          "manual checks\n  (safechecks.py"
          + (", skipped: --no-safe-checks" if args.no_safe_checks else "")
          + "). Risky checks, credential testing and exploits never run "
          "—\n  they're listed in FINDINGS.md and "
          "docs/workflow/MANDATORY_CHECKS.md for you to decide on.")
    if not (args.yes or ask_yes("  Proceed with recon? [y/N] ")):
        log("aborted — nothing was run", "!")
        sys.exit(0)
    # Metasploit: --msf says yes; -y alone (scripted run) means no.
    run_msf_now = args.msf or (not args.yes and ask_yes(
        "  Also run the Metasploit modules automatically? [y/N] "))

    global _OUTDIR
    if os.path.isdir(args.outdir):
        if os.listdir(args.outdir):
            log(f"output folder {args.outdir} already has files — the earlier "
                "run's generated output is replaced; manual-checklist.md, "
                "evidence/ and msf-manual*.log are kept", "-")
            clear_generated(args.outdir, args.from_xml, run_msf_now)
        log(f"output folder: {os.path.abspath(args.outdir)}")
    else:
        os.makedirs(args.outdir)
        # Results are client data: keep a new folder out of git wherever it is.
        with open(os.path.join(args.outdir, ".gitignore"), "w") as f:
            f.write("# ReconFlow results — never commit\n*\n")
        log(f"output folder: {os.path.abspath(args.outdir)} (created)")
    _OUTDIR = args.outdir

    # Scope files actually used are written (comments stripped) into outdir,
    # so every run records exactly what was in and out of scope.
    targets_file = exclude_file = None
    if excluded:
        exclude_file = os.path.join(args.outdir, "scope-excluded.txt")
        with open(exclude_file, "w") as f:
            f.write("\n".join(excluded) + "\n")
    if not args.from_xml:
        targets_file = os.path.join(args.outdir, "scope-inscope.txt")
        with open(targets_file, "w") as f:
            f.write("\n".join(inscope) + "\n")
        xmls, sweep = nmap_scan(targets_file, args.outdir, not args.no_udp,
                                args.top_udp, args.extra, args.timing, manual,
                                not args.quick, exclude_file, args.pn)
    else:
        xmls, sweep = args.from_xml, []

    records = parse_nmap(xmls)
    hosts, scan_cmds = host_info(xmls + sweep)
    # Second line of defence (and the only one for --from-xml): drop any
    # out-of-scope host before a single check, screenshot or module runs.
    def outside(ip, hostname):
        if in_excluded(ip, hostname):
            return True
        return bool(args.from_xml and inscope) and not in_scope(ip, hostname)
    in_scope = scope_matcher(inscope)
    dropped = sorted({ip for ip, h in hosts.items()
                      if outside(ip, h["hostname"])}
                     | {r["ip"] for r in records
                        if outside(r["ip"], r["hostname"])})
    if dropped:
        log(f"ignoring {len(dropped)} out-of-scope host(s) found in the scan "
            f"data: {', '.join(dropped)}", "!")
        records = [r for r in records if r["ip"] not in dropped]
        hosts = {ip: h for ip, h in hosts.items() if ip not in dropped}
        manual["auto"].append((
            f"{len(dropped)} out-of-scope host(s) in the scan data were ignored",
            [f"Hosts: {', '.join(dropped)}",
             "Nothing was run against them; they are removed from the msf "
             "workspace after import."]))
    log(f"parsed {len(records)} open ports across "
        f"{len({r['ip'] for r in records})} hosts")
    quiet = sorted(set(hosts) - {r["ip"] for r in records})
    if quiet:
        log(f"{len(quiet)} host(s) up with no open ports: {', '.join(quiet)}",
            "-")
        manual["auto"].append((
            f"{len(quiet)} host(s) up but no open ports found",
            [f"Hosts: {', '.join(quiet)}",
             "Likely filtered — try all ports / UDP: "
             f"`sudo nmap -Pn -p- -sV {' '.join(quiet)}` and "
             f"`sudo nmap -Pn -sU --top-ports 100 {' '.join(quiet)}`"]))

    if not records:
        # Still write the report: its Manual follow-up says why (hosts down,
        # no root, --quick, ...) and what to try next.
        log("nothing open — writing the report with the follow-up hints", "-")
        write_results(
            args.outdir, records=[], hosts=hosts, scan_cmds=scan_cmds,
            scan_xml=[os.path.abspath(x) for x in xmls], jobs=[], risky=[],
            manual=manual, dropped=dropped, msf_ran=False,
            targets_file=targets_file and os.path.basename(targets_file),
            exclude_file=exclude_file and os.path.basename(exclude_file))
        sys.modules.setdefault("reconflow", sys.modules[__name__])
        import report
        print_manual_banner(manual, report.build(args.outdir))
        return

    write_service_files(records, args.outdir)

    for r in records:  # fall back to -sV "Service Info: OS" when no -O
        if r["ostype"] and r["ip"] in hosts and not hosts[r["ip"]]["os"]:
            hosts[r["ip"]]["os"] = r["ostype"] + " (service banner)"
    if not args.no_screens:
        screenshot(build_web_urls(records), args.outdir, manual)

    jobs = []
    if not args.no_checks:
        jobs = run_checks(records, args.outdir, args.threads,
                          args.check_timeout, manual)

    write_needs_attention(records, args.outdir, manual)

    plain = no_starttls(records)
    if plain:
        manual["auto"].append((
            f"{len(plain)} service(s) offered no TLS in the scan — TLS checks "
            "skipped",
            [f"{r['ip']}:{r['port']} {svc_name(r)}" for r in plain]
            + ["nmap's ssl-cert script found no certificate (no STARTTLS). "
               "Cleartext login on these is a finding; to double-check TLS: "
               "`sslscan --starttls-<proto> TARGET:PORT`."]))

    risky = plan_risky(records)
    if risky:
        manual["auto"].insert(0, (
            f"{len(risky)} risky check(s) NOT run — run by hand only if in "
            "scope (manual-checklist.md → section 1)",
            [f"`{c}`" for e in risky for c in e["cmds"]]
            + ["Why manual: they act on the target (login attempt, relay "
               "test, username guessing, fetching through a proxy, remote "
               "class loading). See docs/workflow/MANDATORY_CHECKS.md."]))
    logins = login_item(records)
    if logins:
        manual["auto"].insert(1 if risky else 0, logins)

    ws = _ws_name(args.outdir)
    rc = write_msf_rc(records, xmls, args.outdir, dropped, ws)
    manual_rc = write_msf_manual_rc(xmls, args.outdir, dropped, ws)
    msf_ran = False
    if run_msf_now:
        msf_ran = run_msf(rc, args.outdir, manual)
        parse_msf_log(args.outdir, manual)
    else:
        manual["auto"].append((
            "Metasploit modules not run (you chose to run them yourself)",
            [f"All at once: `cd {shlex.quote(os.path.abspath(args.outdir))} && msfconsole -r "
             "metasploit.rc`",
             "Module by module: docs/workflow/MANUAL_METASPLOIT.md — start with "
             f"`msfconsole -r {shlex.quote(os.path.abspath(manual_rc))}` "
             "so the session is spooled to msf-manual.log for report.py"]))

    write_target_files(records, args.outdir)
    os.makedirs(os.path.join(args.outdir, "evidence"), exist_ok=True)
    if not args.no_safe_checks:
        run_safe_checks(args, manual)
    write_results(
        args.outdir, records=records, hosts=hosts, scan_cmds=scan_cmds,
        scan_xml=[os.path.abspath(x) for x in xmls], jobs=jobs, risky=risky,
        manual=manual, dropped=dropped, msf_ran=msf_ran, msf_workspace=ws,
        targets_file=targets_file and os.path.basename(targets_file),
        exclude_file=exclude_file and os.path.basename(exclude_file))
    # The report is built by report.py — the same code you re-run later.
    sys.modules.setdefault("reconflow", sys.modules[__name__])
    import report
    report_path = report.build(args.outdir)

    q = shlex.quote(os.path.abspath(args.outdir))
    log(f"DONE. Results in {args.outdir}/", "+")
    log("  FINDINGS.md                the report: findings + how to reproduce",
        "+")
    log("  vulnerabilities/           one file per finding, with evidence", "+")
    log("  SAFE-CHECKS.md             every file the safe checks saved "
        "(in evidence/)", "+")
    log("  manual-checklist.md        commands for manual verification — "
        "tick results here", "+")
    log("  scan-tcp.* / scan-udp.*    full nmap output (all formats)", "+")
    log("  web-report.html            web links + screenshots (http+https)", "+")
    log("  service-checks/            per-port check output + commands.sh", "+")
    log("  open-ports/  targets/      per-service host:port lists / IP lists",
        "+")
    log("  needs-attention/           services with no automation", "+")
    log("  metasploit.rc              workspace + db_import + per-port", "+")
    log("  msf-manual.rc              start your own msfconsole session "
        "(spooled for the report)", "+")
    if not run_msf_now:
        log(f"  -> run msf:  cd {q} && msfconsole -r metasploit.rc", "*")
    log(f"  -> msf by hand:  msfconsole -r {q}/msf-manual.rc", "*")
    log(f"  -> after any manual work:  python3 report.py {q}   "
        "(rebuilds the report; never touches a target)", "*")
    print_manual_banner(manual, report_path)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        kill_running()
        print()
        log("interrupted — every running tool was stopped", "!")
        sys.exit(130)
    finally:
        # Even after a crash or Ctrl-C, the real user (not root) owns what
        # was written, so report.py and the manual steps work without sudo.
        if _OUTDIR and os.path.isdir(_OUTDIR):
            give_to_sudo_user(_OUTDIR)
