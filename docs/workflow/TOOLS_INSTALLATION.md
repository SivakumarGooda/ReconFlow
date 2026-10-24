# Tools — Requirements & Installation

> **Step 1 of 5** · [the whole picture](../README.md) · next: run the scan ([README → Quick start](../../README.md#quick-start))

ReconFlow shells out to standard tooling and **degrades gracefully**: a missing
optional tool means that step is skipped and logged, never a crash. Skipped
commands are listed in `FINDINGS.md` under *Manual follow-up*.

## Contents

- [Requirements](#requirements)
- [Install on Kali](#install-on-kali)
- [Install on Ubuntu / Debian](#install-on-ubuntu--debian)
- [Verify](#verify)
- [First run](#first-run)

---

## Requirements

### Required

| Tool | Purpose |
|---|---|
| Python 3.8+ | runs `reconflow.py` and `report.py` (standard library only) |
| nmap | TCP/UDP scan, version detection, NSE scripts, all output formats (`-oA`) |

### For the Metasploit step

| Tool | Purpose |
|---|---|
| metasploit-framework | `db_import`, workspace, auxiliary modules |
| postgresql + `msfdb` | the database that `db_import` and `services -R` need |

### Optional — each one unlocks a feature

| Tool (package) | Unlocks |
|---|---|
| gowitness **or** httpx-toolkit (ProjectDiscovery httpx) | web screenshots → `web-report.html` |
| curl, whatweb | web header / technology fingerprint checks |
| sslscan, openssl | SSL/TLS protocol, cipher and certificate checks |
| smbclient, enum4linux-ng, netexec (`nxc`) | SMB enumeration |
| snmpwalk (`snmp`) | SNMP checks |
| ldapsearch (`ldap-utils`) | LDAP checks |
| showmount (`nfs-common`) | NFS export checks |
| rpcinfo (`rpcbind`) | RPC program listing |
| impacket-rpcdump (`impacket`) | MSRPC endpoint dump |
| ssh-audit | SSH algorithm audit |
| dig (`dnsutils` / `bind9-dnsutils`) | DNS version check |
| redis-cli (`redis-tools`), rsync | Redis / rsync checks |
| nmblookup (`samba-common-bin`), svn (`subversion`) | NetBIOS names / Subversion checks |
| seclists | wordlists for the credential tests in MANDATORY_CHECKS.md |

> [!NOTE]
> On Kali a plain `httpx` may be the unrelated Python HTTP client.
> ReconFlow only uses `httpx` if it is ProjectDiscovery's; otherwise it looks
> for `httpx-toolkit`.

### For the safe checks (optional)

The safe checks (`safechecks.py`, run by `reconflow.py` at the end of every
scan) use these. A missing one only skips its check — the report lists it
under *Manual follow-up*.

| Tool (package) | Safe check |
|---|---|
| searchsploit (`exploitdb`) | public exploits matching the scanned versions (offline) |
| ike-scan | IKE / VPN main-mode handshake |
| tftp (`tftp-hpa`), finger, nc (`netcat-openbsd`) | TFTP, finger, NNTP, Zookeeper |
| mosquitto_sub (`mosquitto-clients`) | MQTT topics |
| ffprobe (`ffmpeg`) | RTSP camera streams |
| etcdctl (`etcd-client`) | etcd key names |
| iscsiadm (`open-iscsi`) | iSCSI discovery (root) |
| xdpyinfo (`x11-utils`) | X11 display info |
| testssl.sh | full TLS audit (only with `--testssl`) |
| cqlsh (`pipx install cqlsh`), mongosh ([MongoDB's installer](https://www.mongodb.com/try/download/shell)) | Cassandra / MongoDB anonymous access — not in the Kali repos |

### For the manual steps

ReconFlow itself needs only the tools above. The checks in
[MANDATORY_CHECKS.md](MANDATORY_CHECKS.md) name the client tool each one
uses — install those as your engagement's scope requires.

---

## Install on Kali

Most of this is already present on Kali.

```bash
sudo apt update
sudo apt install -y nmap metasploit-framework postgresql smbclient snmp \
    ldap-utils nfs-common seclists enum4linux-ng curl whatweb ssh-audit \
    bind9-dnsutils rpcbind python3-impacket redis-tools rsync \
    httpx-toolkit sslscan samba-common-bin subversion
sudo apt install -y gowitness || go install github.com/sensepost/gowitness@latest
sudo apt install -y netexec   || pipx install netexec

# safe checks (optional)
sudo apt install -y exploitdb ike-scan tftp-hpa finger netcat-openbsd \
    mosquitto-clients ffmpeg etcd-client open-iscsi x11-utils testssl.sh
pipx install cqlsh

sudo msfdb init    # initialise + start the Metasploit database
```

## Install on Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y python3 nmap postgresql smbclient snmp ldap-utils \
    nfs-common golang-go git curl whatweb dnsutils rpcbind redis-tools \
    rsync sslscan samba-common-bin subversion pipx
pipx install ssh-audit
pipx install impacket
pipx install netexec
pipx install enum4linux-ng

# Metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall && sudo ./msfinstall
sudo msfdb init

# gowitness (needs Chrome / Chromium)
sudo apt install -y chromium-browser
go install github.com/sensepost/gowitness@latest

# SecLists
sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

> [!TIP]
> Put `go install` binaries on your PATH:
> `echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc && source ~/.bashrc`

---

## Verify

```bash
for t in nmap msfconsole gowitness httpx-toolkit curl whatweb sslscan openssl \
         smbclient enum4linux-ng nxc snmpwalk ldapsearch showmount rpcinfo \
         impacket-rpcdump ssh-audit dig redis-cli rsync nmblookup svn \
         searchsploit ike-scan tftp finger nc mosquitto_sub ffprobe etcdctl \
         iscsiadm xdpyinfo testssl.sh cqlsh mongosh; do
  command -v "$t" >/dev/null && echo "OK  $t" || echo "--  $t (optional)"
done

msfconsole -qx "db_status; exit"    # should say "connected"
```

---

## First run

```bash
# 1. Add your targets (nano creates the file if it doesn't exist)
nano scope/inscope_ips.txt          # what you may test, one per line
nano scope/outofscope_ips.txt       # hosts to carve out (optional)

# 2. Run it
sudo python3 reconflow.py -o recon-clientA

# 3. Only if you answered N to Metasploit: MANUAL_METASPLOIT.md
# 4. Always: MANDATORY_CHECKS.md

# 5. Fold your manual results in — rebuilds the report, never touches a target
python3 report.py recon-clientA
```

See [scope/ips.example.md](../../scope/ips.example.md) for the file syntax.

ReconFlow then shows the scope and asks two questions: **Proceed with
recon?** and **Also run the Metasploit modules automatically?**
([README → The two questions](../../README.md#the-two-questions)).

Run as root for the full picture. Without root the script still runs, but
falls back to a connect scan (`-sT`) with no OS detection and no UDP, and lists
that under *Manual follow-up*.

If Metasploit didn't run (not installed, or the database is down), the report
says so; run it later with:

```bash
cd recon-clientA && msfconsole -r metasploit.rc
```

All flags, the scope files and the output layout are described in the
[README](../../README.md#usage).
