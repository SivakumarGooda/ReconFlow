# Scope files — syntax and example

ReconFlow reads two plain-text files from this folder:

| File | What goes in it | Override with |
|---|---|---|
| `inscope_ips.txt` | what you are allowed to test | `-iL FILE` |
| `outofscope_ips.txt` | hosts carved out of the in-scope list — never scanned, checked or sent to Metasploit (optional) | `-x FILE` |

Create or edit them with:

```bash
# 1. Add your targets (nano creates the file if it doesn't exist)
nano scope/inscope_ips.txt          # what you may test, one per line
nano scope/outofscope_ips.txt       # hosts to carve out (optional)

# 2. Run it
sudo python3 reconflow.py -o recon-clientA
```

## Syntax

- One target per line, or several on a line separated by spaces.
- Blank lines and `#` comments are ignored (a comment can follow a target).
- Accepted formats:

| Format | Example |
|---|---|
| Single IP | `203.0.113.5` |
| CIDR | `192.0.2.0/24` |
| Range in the last octet | `198.51.100.10-50` |
| Ranges / wildcards in any octet | `10.0.1-3.*` |
| Hostname | `app.example.com` — **in-scope file only**, see below |

## Example

The addresses below are RFC 5737 documentation ranges — replace them with
your engagement's scope.

**`inscope_ips.txt`**

```text
192.0.2.0/24
198.51.100.10-50
203.0.113.5
```

**`outofscope_ips.txt`** — for the scope above

```text
192.0.2.1             # gateway
192.0.2.100-120       # production cluster
198.51.100.25
```

Result: everything in `192.0.2.0/24` except `.1` and `.100`–`.120`, plus
`198.51.100.10`–`.50` except `.25`, plus `203.0.113.5`.

## Use IPs, not hostnames, in the out-of-scope file

> [!IMPORTANT]
> A hostname in `outofscope_ips.txt` can slip through two ways:
>
> 1. nmap excludes only the *first* address a hostname resolves to — if it
>    has several IPs, the others can still be scanned when they sit inside an
>    in-scope subnet.
> 2. ReconFlow's second filter can only recognise a hostname if nmap's
>    reverse-DNS lookup reports the same name for that IP, which often it
>    doesn't.
>
> An IP means exactly one machine, so it can't be missed. Hostnames are fine
> in `inscope_ips.txt`. ReconFlow prints a warning if it finds a hostname in
> the out-of-scope file.

See also: [README → Scope files](../README.md#scope-files).
