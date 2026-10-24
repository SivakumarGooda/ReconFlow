# shellcheck shell=bash
# =============================================================================
# ReconFlow helpers — run a manual check against EVERY target, not just one.
# Used by docs/workflow/MANDATORY_CHECKS.md. Never run by ReconFlow itself.
#
#   cd <output folder>                       # the -o folder
#   source /path/to/ReconFlow/tools/rf-helpers.sh
#
# A SOURCE is where the targets come from:
#   ftp, tcp-ftp, udp-snmp, web, ssl, ...   -> every targets/port-<N>-<proto>-<svc>.txt
#                                              (every port the service was found on;
#                                               "ftp" alone = tcp and udp files)
#   445-tcp-smb                              -> one port only: targets/port-445-tcp-smb.txt
#   vulnerabilities/hosts/<finding>.txt      -> the exact ip:port list of one finding
#   any file of ip:port lines
#
# each NAME SOURCE 'command'       run once per host:port; $T = IP, $P = port.
#                                  Output: evidence/NAME_<T>_<P>_1.txt
# each_file NAME SOURCE 'command'  run once per targets file (tools that take a
#                                  host list); $F = the file, $P = its port.
#                                  Output: evidence/NAME_port-<P>_1.txt
# msf_rc NAME SOURCE MODULE ['set OPT val' ...]
#                                  write msf-blocks/NAME.rc — one block per port
#                                  (RHOSTS file:...) or per ip:port line. Run it
#                                  inside msfconsole: resource msf-blocks/NAME.rc
#
# Settings (environment variables):
#   RF_DRY=1          print what would run, run nothing
#   RF_TIMEOUT=60     seconds per host for `each` (each_file: RF_TIMEOUT_FILE=1800)
#   RF_N=1            the _N at the end of evidence names (2 for a second step)
#   RF_MSF_ACTION=run what msf_rc ends each block with (check for exploits)
#
# Works when sourced from bash or zsh.
# Commands run with stdin closed, so nothing waits for input; anything that
# needs a password (sudo) — run `sudo -v` first.
# =============================================================================

_rf_here() {
    if [ ! -d targets ]; then
        echo "rf: no targets/ folder here — cd into the ReconFlow output folder first" >&2
        return 1
    fi
    mkdir -p evidence
}

# _rf_files SOURCE -> the targets/ files for a service name
_rf_files() {
    [ -n "${ZSH_VERSION:-}" ] && setopt localoptions shwordsplit nullglob
    local src=$1 f
    case $src in
        [0-9]*-tcp-*|[0-9]*-udp-*) set -- targets/port-"$src".txt ;;
        tcp-*|udp-*) set -- targets/port-*-"$src".txt ;;
        *)           set -- targets/port-*-tcp-"$src".txt targets/port-*-udp-"$src".txt ;;
    esac
    for f in "$@"; do [ -e "$f" ] && echo "$f"; done
}

# _rf_port FILE -> the port from targets/port-<N>-<proto>-<svc>.txt
_rf_port() { basename "$1" | cut -d- -f2; }

# _rf_pairs SOURCE -> "ip port" lines
_rf_pairs() {
    [ -n "${ZSH_VERSION:-}" ] && setopt localoptions shwordsplit nullglob
    local src=$1 f p
    if [ -f "$src" ]; then
        sed -E 's/#.*//; s#/(tcp|udp)[[:space:]]*$##' "$src" |
            awk -F: 'NF == 2 && $1 != "" && $2 ~ /^[0-9]+[[:space:]]*$/ {gsub(/[[:space:]]/, ""); print $1, $2}'
        return
    fi
    for f in $(_rf_files "$src"); do
        p=$(_rf_port "$f")
        awk -v p="$p" 'NF {print $1, p}' "$f"
    done
}

each() {
    [ -n "${ZSH_VERSION:-}" ] && setopt localoptions shwordsplit nullglob
    if [ $# -ne 3 ]; then
        echo "usage: each NAME SOURCE 'command using \$T and \$P'" >&2
        return 2
    fi
    _rf_here || return 1
    local name=$1 src=$2 cmd=$3 pairs out n=0 T P
    pairs=$(_rf_pairs "$src")
    if [ -z "$pairs" ]; then
        echo "rf: $name — no targets for '$src' (service not found in this scan) — skipped"
        return 0
    fi
    while read -r T P; do
        n=$((n + 1))
        out="evidence/${name}_${T}_${P}_${RF_N:-1}.txt"
        if [ -n "$RF_DRY" ]; then
            printf '[dry] T=%s P=%s  %s   -> %s\n' "$T" "$P" "$cmd" "$out"
            continue
        fi
        echo "== $name  $T:$P  -> $out"
        {
            printf '$ T=%s P=%s; %s\n' "$T" "$P" "$cmd"
            T=$T P=$P timeout -k 5 "${RF_TIMEOUT:-60}" bash -c "$cmd" </dev/null 2>&1
            [ $? -eq 124 ] && echo "(stopped after ${RF_TIMEOUT:-60}s — RF_TIMEOUT)"
        } | tee "$out"
    done <<< "$pairs"
    echo "rf: $name — $n target(s)$([ -n "$RF_DRY" ] && echo ', dry run'); output: evidence/${name}_*"
}

each_file() {
    [ -n "${ZSH_VERSION:-}" ] && setopt localoptions shwordsplit nullglob
    if [ $# -ne 3 ]; then
        echo "usage: each_file NAME SOURCE 'command using \$F and \$P'" >&2
        return 2
    fi
    _rf_here || return 1
    local name=$1 src=$2 cmd=$3 F P out n=0
    for F in $(_rf_files "$src"); do
        n=$((n + 1))
        P=$(_rf_port "$F")
        out="evidence/${name}_port-${P}_${RF_N:-1}.txt"
        if [ -n "$RF_DRY" ]; then
            printf '[dry] F=%s P=%s  %s   -> %s\n' "$F" "$P" "$cmd" "$out"
            continue
        fi
        echo "== $name  $F  -> $out"
        {
            printf '$ F=%s P=%s; %s\n' "$F" "$P" "$cmd"
            F=$F P=$P timeout -k 5 "${RF_TIMEOUT_FILE:-1800}" bash -c "$cmd" </dev/null 2>&1
        } | tee "$out"
    done
    if [ $n -eq 0 ]; then
        echo "rf: $name — no targets for '$src' (service not found in this scan) — skipped"
    else
        echo "rf: $name — $n port file(s); output: evidence/${name}_*"
    fi
}

msf_rc() {
    [ -n "${ZSH_VERSION:-}" ] && setopt localoptions shwordsplit nullglob
    if [ $# -lt 3 ]; then
        echo "usage: msf_rc NAME SOURCE MODULE ['set OPT value' ...]" >&2
        return 2
    fi
    _rf_here || return 1
    local name=$1 src=$2 mod=$3 act=${RF_MSF_ACTION:-run} rc f p T P n=0 line
    shift 3
    mkdir -p msf-blocks
    rc="msf-blocks/${name}.rc"
    {
        # msfconsole keeps a trailing "# ..." as part of a value: comments
        # only ever on their own line.
        echo "# ReconFlow — $mod against $src (written by msf_rc)"
        if [ -f "$src" ]; then
            while read -r T P; do
                [ -n "$T" ] || continue
                n=$((n + 1))
                printf 'use %s\nset RHOSTS %s\nset RPORT %s\n' "$mod" "$T" "$P"
                for line in "$@"; do printf '%s\n' "$line"; done
                printf '%s\nback\n' "$act"
            done <<< "$(_rf_pairs "$src")"
        else
            for f in $(_rf_files "$src"); do
                n=$((n + 1))
                p=$(_rf_port "$f")
                printf 'use %s\nset RHOSTS file:%s\nset RPORT %s\n' "$mod" "$f" "$p"
                for line in "$@"; do printf '%s\n' "$line"; done
                printf '%s\nback\n' "$act"
            done
        fi
    } > "$rc"
    if ! grep -q '^use ' "$rc"; then
        rm -f "$rc"
        echo "rf: $name — no targets for '$src' (service not found in this scan) — no rc written"
        return 0
    fi
    echo "rf: wrote $rc ($(grep -c '^use ' "$rc") block(s), ends with '$act')."
    echo "    In msfconsole (started with msf-manual.rc, so it's spooled):  resource $rc"
}
