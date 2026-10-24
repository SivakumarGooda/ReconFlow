#!/usr/bin/env python3
"""
ReconFlow rule tests — saved tool output in, findings out. No network, no
target, standard library only:

    python3 -m unittest discover -s tests -v      (from the ReconFlow folder)

Each detection rule (OUTPUT_RULES, VERSION_RULES, MSF_RULES, the TLS / NFS /
SMB / NSE parsers) gets a sample of the real tool's output. When you add or
change a rule, add its sample here, so a typo or a tool's changed wording
shows up as a failing test instead of a silently missed finding.
"""

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import reconflow as rf  # noqa: E402
import report  # noqa: E402

IP = "192.0.2.10"


def rec(port, name="", proto="tcp", tunnel="", product="", version="",
        tls=None):
    return {"ip": IP, "hostname": "", "port": port, "proto": proto,
            "name": name, "product": product, "version": version,
            "extrainfo": "", "tunnel": tunnel, "ostype": "", "tls": tls}


def findings(out, prof, port=1, cmd="nmap x", proto="tcp"):
    """Run one fake check output through analyze() -> {fid: [entries]}."""
    job = {"group": "g", "ip": IP, "port": port, "proto": proto,
           "prof": prof, "tool": "nmap", "cmd": cmd, "status": "ok",
           "out": out}
    return {fid: list(v.values())
            for fid, v in rf.analyze([], [job]).items()}


# ---------------------------------------------------------------------------
# Check-output samples: (profile, output, expected finding id)
# ---------------------------------------------------------------------------

OUTPUT_SAMPLES = [
    ("ftp", "21/tcp open  ftp\n| ftp-anon: Anonymous FTP login allowed "
            "(FTP code 230)\n|_drwxr-xr-x    2 0  65534  4096 pub\n",
     "ftp-anon"),
    ("smb", "| smb-security-mode: \n|   account_used: guest\n"
            "|   message_signing: disabled (dangerous, but default)\n",
     "smb-signing"),
    ("smb", "| smb2-security-mode: \n|   3:1:1: \n"
            "|_    Message signing enabled but not required\n",
     "smb-signing"),
    ("smb", "SMB  192.0.2.10  445  HOST  [*] Unix (name:HOST) "
            "(domain:x) (signing:False) (SMBv1:True)\n", "smb-signing"),
    ("smb", "[+] Server allows session using username '', password ''\n",
     "smb-null"),
    ("smtp", "| smtp-commands: host, PIPELINING, SIZE, VRFY, ETRN, "
             "STARTTLS, 8BITMIME\n", "smtp-vrfy"),
    ("smtp", "| smtp-enum-users: \n|_  root\n", "smtp-user-enum"),
    ("smtp", "| smtp-open-relay: Server is an open relay (16/16 tests)\n",
     "smtp-open-relay"),
    ("mysql", "| mysql-empty-password: \n|_  root account has empty "
              "password\n", "mysql-empty"),
    ("x11", "|_x11-access: X server access is granted\n", "x11-open"),
    ("dns", "|_dns-recursion: Recursion appears to be enabled\n",
     "dns-recursion"),
    ("nfs", "Export list for 192.0.2.10:\n/srv/share *\n", "nfs-exports"),
    ("redis", "# Server\nredis_version:5.0.7\nredis_mode:standalone\n",
     "redis-unauth"),
    ("docker", '{"Platform":{"Name":"Docker Engine"},"ApiVersion":"1.41"}',
     "docker-unauth"),
    ("elasticsearch", '{"name":"n1","cluster_name":"prod","version":{}}',
     "es-unauth"),
    ("snmp", "SNMPv2-MIB::sysDescr.0 = STRING: Linux host 5.4\n",
     "snmp-public"),
    ("proxy", "| http-open-proxy: Potentially OPEN proxy.\n", "open-proxy"),
    ("mqtt", "| mqtt-subscribe: \n|   Topics and their most recent "
             "payloads: \n", "mqtt-anon"),
    ("couchdb", '["_replicator","_users","customers"]\n', "couchdb-unauth"),
    ("kubelet", '{"kind":"PodList","apiVersion":"v1","items":[]}',
     "kubelet-unauth"),
    ("etcd", '{"etcdserver":"3.4.13","etcdcluster":"3.4.0"}',
     "etcd-unauth"),
    ("irc", "|_irc-unrealircd-backdoor: Looks like trojaned version of "
            "unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277\n",
     "unrealircd"),
]


class OutputRules(unittest.TestCase):
    def test_every_output_rule_has_a_sample(self):
        covered = {fid for _, _, fid in OUTPUT_SAMPLES}
        missing = {fid for _, fid in rf.OUTPUT_RULES} - covered
        self.assertFalse(missing, f"OUTPUT_RULES without a sample: {missing}")

    def test_samples_match(self):
        for prof, out, fid in OUTPUT_SAMPLES:
            with self.subTest(fid=fid, prof=prof):
                self.assertIn(fid, findings(out, prof))

    def test_profile_bound_rules_stay_in_their_profile(self):
        # A JSON list from some other service is not CouchDB.
        self.assertNotIn("couchdb-unauth", findings('["a","b"]', "web"))

    def test_clean_output_gives_nothing(self):
        out = ("| smb2-security-mode: \n|   3:1:1: \n"
               "|_    Message signing enabled and required\n"
               "| ftp-anon: \n|_  Anonymous login denied\n")
        self.assertEqual(findings(out, "smb"), {})


class VersionRules(unittest.TestCase):
    CASES = [
        (rec(21, "ftp", product="vsftpd", version="2.3.4"), "vsftpd-234"),
        (rec(2121, "ftp", product="ProFTPD", version="1.3.3c"),
         "proftpd-133c"),
        (rec(6667, "irc", product="UnrealIRCd"), "unrealircd"),
        (rec(445, "netbios-ssn", product="Samba smbd",
             version="3.0.20-Debian"), "samba-usermap"),
        (rec(3632, "distccd", product="distccd"), "distcc"),
        (rec(1524, "bindshell", product="Metasploitable root shell"),
         "bindshell"),
        (rec(8787, "drb", product="Ruby DRb RMI"), "drb"),
        (rec(1099, "java-rmi", product="GNU Classpath grmiregistry"),
         "java-rmi"),
        (rec(8180, "http", product="Apache Tomcat/Coyote JSP engine"),
         "tomcat"),
        (rec(8000, "jdwp", product="Java Debug Wire Protocol"), "jdwp"),
        (rec(23, "telnet", product="Linux telnetd"), "telnet"),
        (rec(512, "exec", product="netkit-rsh rexecd"), "r-services"),
    ]

    def test_every_version_rule_has_a_case(self):
        covered = {fid for _, fid in self.CASES}
        missing = {fid for _, fid in rf.VERSION_RULES} - covered
        self.assertFalse(missing, f"VERSION_RULES without a case: {missing}")

    def test_cases(self):
        for r, fid in self.CASES:
            with self.subTest(fid=fid):
                self.assertIn(fid, dict(rf.known_bad([r])))

    def test_near_misses(self):
        hits = dict(rf.known_bad([
            rec(21, "ftp", product="vsftpd", version="2.3.5"),
            rec(445, "netbios-ssn", product="Samba smbd", version="3.0.26"),
            rec(69, "tftp")]))
        self.assertEqual(hits, {})


class Parsers(unittest.TestCase):
    def test_nse_vulnerable_and_not(self):
        out = ("| smb-vuln-ms17-010: \n|   VULNERABLE:\n"
               "|   Remote Code Execution vulnerability in Microsoft SMBv1 "
               "servers (ms17-010)\n|     State: VULNERABLE\n|     IDs:  "
               "CVE:CVE-2017-0143\n"
               "| ssl-ccs-injection: \n|   NOT VULNERABLE:\n"
               "|_    State: NOT VULNERABLE\n")
        got = rf._nse_vulns(out)
        self.assertEqual([s for s, _, _ in got], ["smb-vuln-ms17-010"])
        self.assertIn("ms17-010", got[0][1])

    def test_nse_finding_title_and_severity(self):
        f = findings("| ssl-heartbleed: \n|   VULNERABLE:\n|   The Heartbleed"
                     " Bug is a serious vulnerability\n|     State: "
                     "VULNERABLE\n", "ssl", port=443)
        self.assertIn("nse:ssl-heartbleed", f)
        info = rf.finding_info("nse:ssl-heartbleed", f["nse:ssl-heartbleed"])
        self.assertEqual(info["sev"], "Critical")

    def test_tls(self):
        out = ("| ssl-cert: Subject: commonName=box\n"
               "| Issuer: commonName=box\n"
               "| Not valid after:  2001-01-01T00:00:00\n"
               "| ssl-enum-ciphers: \n|   TLSv1.0: \n|     ciphers: \n"
               "|   TLSv1.2: \n|_  least strength: C\n")
        fids = {f for f, _, _ in rf._ssl_findings(out)}
        self.assertEqual(fids, {"tls-old-proto", "tls-weak-cipher",
                                "tls-cert-expired", "tls-self-signed"})

    def test_tls_clean(self):
        out = ("| ssl-cert: Subject: commonName=box\n"
               "| Issuer: commonName=Some CA\n"
               "| Not valid after:  2999-01-01T00:00:00\n"
               "| ssl-enum-ciphers: \n|   TLSv1.2: \n"
               "|_  least strength: A\n")
        self.assertEqual(rf._ssl_findings(out), [])

    def test_nfs_root_and_writable(self):
        out = ("Export list for 192.0.2.10:\n/ *\n/home 10.0.0.0/8\n"
               "| nfs-ls: Volume /home\n|   access: Read Lookup Modify "
               "Extend Delete NoExecute\n")
        fids = [f for f, _, _ in rf._nfs_findings(out)]
        self.assertIn("nfs-root-export", fids)
        self.assertIn("nfs-writable", fids)

    def test_smb_anon_shares_skip_ipc(self):
        out = ("|   \\\\192.0.2.10\\IPC$: \n|     Anonymous access: READ/WRITE\n"
               "|   \\\\192.0.2.10\\tmp: \n|     Anonymous access: READ/WRITE\n")
        self.assertEqual([s for s, _ in rf._smb_anon_shares(out)],
                         ["tmp (READ/WRITE)"])

    def test_share_name_from_target_is_quoted(self):
        out = ("|   \\\\192.0.2.10\\$(curl${IFS}x|sh): \n"
               "|     Anonymous access: READ\n")
        e = findings(out, "smb", port=445)["smb-share-anon"][0]
        cmd = report._fill(rf.FINDING_INFO["smb-share-anon"]["repro"][0], e)
        self.assertIn("'$(curl${IFS}x|sh)'", cmd)


# ---------------------------------------------------------------------------
# Metasploit logs (strings checked against the module sources)
# ---------------------------------------------------------------------------

MSF_LOG = """\
msf6 > use auxiliary/scanner/ftp/ftp_anonymous
RPORT => 21
[+] 192.0.2.10:21         - 192.0.2.10:21 - Anonymous READ access (220 (vsFTPd 2.3.4))
msf6 auxiliary(scanner/ftp/ftp_anonymous) > use auxiliary/scanner/smb/smb_version
RPORT => 445
[*] 192.0.2.10:445        - SMB Detected (versions:1) (preferred dialect:) (signatures: optional)
msf6 auxiliary(scanner/smb/smb_version) > use auxiliary/scanner/smb/smb_ms17_010
[+] 192.0.2.10:445        - Host is likely VULNERABLE to MS17-010! - Windows 7
msf6 auxiliary(scanner/smb/smb_ms17_010) > use auxiliary/scanner/snmp/snmp_enum
RPORT => 161
[+] 192.0.2.10, Connected.
msf6 auxiliary(scanner/snmp/snmp_enum) > use auxiliary/scanner/nfs/nfsmount
RPORT => 111
[+] 192.0.2.10:111        - 192.0.2.10 Mountable NFS Export: / [*]
msf6 auxiliary(scanner/nfs/nfsmount) > use auxiliary/scanner/ssh/ssh_login
RPORT => 22
[+] 192.0.2.10:22 - Success: 'msfadmin:msfadmin' 'uid=1000(msfadmin)'
msf6 auxiliary(scanner/ssh/ssh_login) > use auxiliary/scanner/redis/redis_server
RPORT => 6379
[+] 192.0.2.10:6379       - Found redis with INFO command: 24 35
[+] 192.0.2.10:6379       - something no rule knows
msf6 auxiliary(scanner/redis/redis_server) > use auxiliary/scanner/rservices/rsh_login
RPORT => 514
[+] 192.0.2.10:514, rsh 'root' from 'root' with no password.
msf6 auxiliary(scanner/rservices/rsh_login) > use exploit/unix/ftp/vsftpd_234_backdoor
RPORT => 21
[+] 192.0.2.10:21 - The target is vulnerable.
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > use auxiliary/scanner/smtp/smtp_relay
RPORT => 25
[+] 192.0.2.10:25         - Potential open SMTP relay detected: - a@x -> b@y
"""


class MsfRules(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "msf-manual.log"), "w") as f:
            f.write(MSF_LOG)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_log_to_findings(self):
        hits = report.parse_msf_log(os.path.join(self.dir, "msf-manual.log"),
                                    "Metasploit (manual)", self.dir)
        found = rf.defaultdict(dict)
        other = report.apply_msf(found, hits, {})
        expect = {"ftp-anon", "smb-signing", "nse:smb-vuln-ms17-010",
                  "snmp-public", "nfs-root-export", "nfs-exports",
                  "weak-creds", "redis-unauth", "vsftpd-234",
                  "smtp-open-relay"}
        self.assertEqual(set(found), expect)
        self.assertIn(514, {e["port"] for e in found["weak-creds"].values()})
        snmp = list(found["snmp-public"].values())[0]
        self.assertEqual(snmp["port"], 161)  # from `RPORT => 161`
        self.assertEqual([h["msg"] for h in other],
                         ["something no rule knows"])


# ---------------------------------------------------------------------------
# Scope, profiles, generated files, process handling
# ---------------------------------------------------------------------------

class Scope(unittest.TestCase):
    def test_matcher(self):
        m = rf.scope_matcher(["10.0.0.0/24", "10.0.1-3.5", "10.9.9.1-50",
                              "db01.corp"])
        self.assertTrue(m("10.0.0.7"))
        self.assertTrue(m("10.0.2.5"))
        self.assertFalse(m("10.0.4.5"))
        self.assertTrue(m("10.9.9.50"))
        self.assertFalse(m("10.9.9.51"))
        self.assertTrue(m("172.16.0.1", "DB01.corp"))
        self.assertFalse(m("172.16.0.1"))


class EvidenceRules(unittest.TestCase):
    """Hand-run / safe-check output (source Manual) judged by EVIDENCE_RULES."""

    def _manual(self, out, prof, port=443):
        job = {"group": "", "ip": IP, "port": port, "proto": "tcp",
               "prof": prof, "cmd": "x", "status": "ok", "out": out,
               "source": "Manual", "evidence": "evidence/x"}
        return rf.analyze([], [job])

    def test_old_tls_accepted(self):
        out = "New, TLSv1, Cipher is ECDHE-RSA-AES256-SHA\n    Protocol  : TLSv1\n"
        self.assertIn("tls-old-proto", self._manual(out, "ssl"))

    def test_old_tls_refused_is_not_a_finding(self):
        out = ("error:0A00042E:SSL routines:ssl3_read_bytes:tlsv1 alert "
               "protocol version\nNew, (NONE), Cipher is (NONE)\n"
               "Protocol: TLSv1\n    Protocol  : TLSv1\n")
        self.assertNotIn("tls-old-proto", self._manual(out, "ssl"))

    def test_modern_tls_is_not_a_finding(self):
        out = "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\n"
        self.assertNotIn("tls-old-proto", self._manual(out, "ssl"))


class SafeChecksReview(unittest.TestCase):
    """safechecks.review_items: ✍️ results that look like an issue, for
    host:ports still in the scan, end up in FINDINGS.md."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.dir, "evidence"))

    def tearDown(self):
        shutil.rmtree(self.dir)

    def _ev(self, name, body):
        with open(os.path.join(self.dir, "evidence", name), "w") as f:
            f.write("$ cmd\n" + body)

    def test_hits_only_for_scanned_hosts(self):
        import safechecks
        self._ev(f"svn-log_{IP}_3690_1.txt", "r12 | bob | 2020-01-01\n")
        self._ev(f"svn-log_198.51.100.9_3690_1.txt", "r12 | bob\n")
        self._ev(f"cups-admin_{IP}_631_1.txt", "403 /admin\n")
        items = safechecks.review_items(self.dir, [rec(3690, "svn"),
                                                   rec(631, "ipp")])
        self.assertEqual([(i["check"], i["target"]) for i in items],
                         [("svn-log", f"{IP}:3690")])
        self.assertEqual(items[0]["repro"],
                         f"T={IP} P=3690 bash -c 'svn log --non-interactive "
                         "-l 20 svn://$T:$P/'")

    def test_auto_checks_are_left_to_the_rules(self):
        import safechecks
        self._ev(f"redis-config_{IP}_6379_1.txt", "redis_version:7\n")
        self.assertEqual(safechecks.review_items(self.dir,
                                                 [rec(6379, "redis")]), [])

    def test_command_line_never_counts_as_a_hit(self):
        import safechecks
        # the first line is the command — it may contain the hit pattern
        with open(os.path.join(self.dir, "evidence",
                               f"cups-admin_{IP}_631_1.txt"), "w") as f:
            f.write('$ curl -w "%{http_code} /admin"\n')
        self.assertEqual(safechecks.review_items(self.dir,
                                                 [rec(631, "ipp")]), [])


class Profiles(unittest.TestCase):
    def test_starttls_only_when_tls_seen_or_unknown(self):
        self.assertIn("ssl", rf.profiles_for(rec(25, "smtp", tls=True)))
        self.assertIn("ssl", rf.profiles_for(rec(25, "smtp", tls=None)))
        self.assertNotIn("ssl", rf.profiles_for(rec(25, "smtp", tls=False)))
        self.assertEqual(len(rf.no_starttls([rec(25, "smtp", tls=False)])), 1)

    def test_tls_port_always_gets_ssl(self):
        self.assertIn("ssl", rf.profiles_for(rec(443, "https", tls=False)))


class Generated(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_scan_never_runs_open_proxy(self):
        self.assertIn("not http-open-proxy", rf.SCAN_SCRIPTS)

    def test_new_workspace_per_run(self):
        a = rf._ws_name(self.dir)
        time.sleep(1.1)
        self.assertNotEqual(a, rf._ws_name(self.dir))

    def test_rc_uses_given_workspace_and_drops_hosts(self):
        rc = rf.write_msf_rc([rec(21, "ftp")], [], self.dir,
                             drop_ips=["192.0.2.99"], ws="wsX")
        with open(rc) as f:
            text = f.read()
        self.assertIn("workspace -a wsX", text)
        self.assertIn("hosts -d 192.0.2.99", text)
        self.assertIn("#   use auxiliary/scanner/ftp/ftp_login", text)
        for line in text.splitlines():  # msfconsole keeps trailing comments
            if not line.startswith("#"):
                self.assertNotIn(" #", line)

    def test_risky_never_in_checks(self):
        risky = {t for pb in rf.PLAYBOOK.values()
                 for _, t, *_ in pb.get("risky", [])}
        checks = {t for pb in rf.PLAYBOOK.values()
                  for _, t in pb.get("checks", [])}
        self.assertFalse(risky & checks)
        for t in checks:
            for script in ("http-open-proxy", "smtp-open-relay",
                           "smtp-enum-users", "mysql-empty-password",
                           "rmi-vuln-classloader"):
                self.assertNotIn(script, t)


class Processes(unittest.TestCase):
    def test_kill_running_stops_a_child(self):
        result = {}
        t = threading.Thread(target=lambda: result.update(
            rc=rf.run(["sleep", "30"], timeout=60)))
        start = time.time()
        t.start()
        time.sleep(0.5)
        rf.kill_running()
        t.join(5)
        self.assertFalse(t.is_alive())
        self.assertLess(time.time() - start, 5)


class ReportFromEvidence(unittest.TestCase):
    """Evidence written by tools/rf-helpers.sh (evidence/<name>_<ip>_<port>_<n>.txt)
    reaches the report without a checklist entry; host lists are written."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        r = rec(21, "ftp", product="vsftpd", version="2.3.4")
        import json
        with open(os.path.join(self.dir, "results.json"), "w") as f:
            json.dump({"records": [r], "hosts": {IP: {"hostname": "", "os": ""}},
                       "scan_cmds": [], "jobs": [], "risky": [],
                       "manual": {"auto": [], "none": []}, "dropped": [],
                       "generated": "now", "scan_xml": []}, f)
        os.makedirs(os.path.join(self.dir, "evidence"))

    def tearDown(self):
        shutil.rmtree(self.dir)

    def _build(self):
        report.build(self.dir, quiet=True)
        with open(os.path.join(self.dir, "FINDINGS.md")) as f:
            return f.read()

    def test_helper_evidence_confirms(self):
        with open(os.path.join(self.dir, "evidence",
                               f"ftp-anon-check_{IP}_21_1.txt"), "w") as f:
            f.write("$ T=x P=21; ftp\n230 Login successful.\n")
        text = self._build()
        self.assertRegex(text, r"FTP anonymous login allowed .*\| Manual \| "
                               r"Confirmed")

    def test_unscanned_host_port_ignored(self):
        with open(os.path.join(self.dir, "evidence",
                               "x_198.51.100.9_21_1.txt"), "w") as f:
            f.write("230 Login successful.\n")
        self.assertNotIn("FTP anonymous", self._build())

    def test_host_lists(self):
        self._build()
        with open(os.path.join(self.dir, "vulnerabilities", "hosts",
                               "vsftpd-234.txt")) as f:
            self.assertEqual(f.read(), f"{IP}:21\n")


if __name__ == "__main__":
    unittest.main()
