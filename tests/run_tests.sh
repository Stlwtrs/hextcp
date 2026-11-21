#!/usr/bin/env bash
#
# Test suite for hextcp. Runs the script against fixture socket tables and a
# fake /proc tree, so results are the same on every machine.
#
# Usage: bash tests/run_tests.sh

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HEXTCP="$HERE/../hextcp.sh"
FIX="$HERE/fixtures"

PASS=0
FAIL=0
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ok()   { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [[ -n "${2:-}" ]] && printf '       %s\n' "$2"; }

assert_contains() {  # name haystack needle
  if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "missing: $3"; fi
}
assert_not_contains() {
  if [[ "$2" != *"$3"* ]]; then ok "$1"; else bad "$1" "unexpected: $3"; fi
}
assert_row() {  # name output text-on-row flag-on-same-row
  if printf '%s\n' "$2" | grep -F -- "$3" | grep -qF -- "$4"; then ok "$1"; else bad "$1" "no row with '$3' and '$4'"; fi
}
assert_eq() {
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "expected '$3', got '$2'"; fi
}

# Fake /proc: three processes owning fixture sockets.
PROC="$WORK/proc"
mkproc() {  # pid comm exe inode
  mkdir -p "$PROC/$1/fd"
  printf '%s\n' "$2" > "$PROC/$1/comm"
  ln -s "$3" "$PROC/$1/exe"
  ln -s "socket:[$4]" "$PROC/$1/fd/3"
}
mkdir -p "$PROC/self/fd"
mkproc 1234 sshd /usr/bin/sshd 1002
mkproc 666 kworkerx "/tmp/.x (deleted)" 1003
mkproc 77 dbus-daemon /usr/bin/dbus-daemon 3001

run() { HEXTCP_NET_DIR="$FIX" HEXTCP_PROC_DIR="$PROC" bash "$HEXTCP" "$@" 2>"$WORK/stderr"; }

valid_json_lines() {
  python3 -c 'import json,sys
for n, l in enumerate(sys.stdin, 1):
    json.loads(l)' 2>&1
}

echo "Decoding"
out=$(run -a)
assert_contains "IPv4 listener"               "$out" "127.0.0.1:3306"
assert_contains "IPv4 remote address"         "$out" "192.168.1.100:54321"
assert_contains "TIME_WAIT state name"        "$out" "TIME_WAIT"
assert_contains "IPv6 unspecified"            "$out" "[::]:80"
assert_contains "IPv6 loopback"               "$out" "[::1]:8080"
assert_contains "IPv4-mapped IPv6"            "$out" "[::ffff:10.0.2.15]:22"
assert_contains "IPv6 link-local"             "$out" "[fe80::25a:50ff:fe12:3456]:53"
assert_contains "IPv6 zero compression"       "$out" "[2001:db8::1]:443"
assert_contains "IPv6 first longest zero run" "$out" "[2001:db8::1:0:0:1]:9000"
assert_contains "tcp6 protocol label"         "$out" "tcp6"

echo "Filtering"
out=$(run)
assert_not_contains "default hides TIME_WAIT" "$out" "TIME_WAIT"
assert_eq "count matches filtered rows" "$(run -c)" "9"
assert_eq "count with -a"               "$(run -a -c)" "10"
assert_eq "IPv4 only"                   "$(run -4 -c)" "3"
assert_eq "IPv6 only"                   "$(run -6 -c)" "6"
assert_contains "UDP unconnected socket" "$(run -U)" "UNCONN"
assert_eq "UDP count"                    "$(run -U -c)" "2"

echo "Processes and alerts"
out=$(run -p -e)
code=$?
assert_contains "process mapped by inode"  "$out" "sshd (1234)"
assert_row "suspicious path flagged"  "$out" "kworkerx (666)" "[!] SUSPICIOUS PATH"
assert_eq "alert exit code" "$code" "3"
out=$(run -w "$FIX/watchlist.txt")
code=$?
assert_row "IPv4 watchlist hit"       "$out" "13.12.11.10:4444" "[!] WATCHLIST"
assert_row "IPv6 watchlist, any case" "$out" "[2001:db8:0:1::abcd]:60000" "[!] WATCHLIST"
assert_eq "only watchlisted rows flagged" "$(printf '%s\n' "$out" | grep -c WATCHLIST)" "2"
assert_eq "watchlist exit code" "$code" "3"
run >/dev/null; assert_eq "no alerts exit code" "$?" "0"

mkdir -p "$WORK/bin"
printf '#!/bin/sh\nexit 1\n' > "$WORK/bin/find"; chmod +x "$WORK/bin/find"
out=$(PATH="$WORK/bin:$PATH" run -p)
assert_contains "process mapping without GNU find (BusyBox fallback)" "$out" "sshd (1234)"

echo "Pure Bash guarantee"
BASH_BIN="$(command -v bash)"
nopath() { env -i PATH=/nonexistent HEXTCP_NET_DIR="$FIX" "$BASH_BIN" "$HEXTCP" "$@" 2>&1; }
assert_contains "decodes TCP and IPv6 with no external commands" "$(nopath -a)" "[2001:db8::1]:443"
assert_contains "UDP with no external commands"         "$(nopath -U)" "UNCONN"
assert_contains "Unix sockets with no external commands" "$(nopath -u)" "/run/dbus/system_bus_socket"
assert_contains "JSON with no external commands"        "$(nopath -j)" '"local_port":3306'
assert_row "watchlist with no external commands" "$(nopath -w "$FIX/watchlist.txt")" "13.12.11.10:4444" "[!] WATCHLIST"
assert_contains "help with no external commands"        "$(nopath -h)" "Usage: hextcp"

echo "Unix sockets"
out=$(run -u -p)
assert_row "listening unix socket" "$out" "/run/dbus/system_bus_socket" "LISTEN"
assert_contains "unix process mapping"    "$out" "dbus-daemon (77)"
assert_contains "abstract socket"         "$out" "@abstract-name"
assert_contains "path with spaces"        "$out" '/tmp/my "odd" socket'
assert_not_contains "unnamed hidden by default" "$out" "(unnamed)"
assert_contains "unnamed shown with -a"   "$(run -u -a)" "(unnamed)"

echo "JSON"
json=$(run -a -p -e -r -w "$FIX/watchlist.txt" -j)
assert_eq "TCP JSON lines are valid"   "$(printf '%s\n' "$json" | valid_json_lines)" ""
assert_eq "one JSON object per socket" "$(printf '%s\n' "$json" | wc -l | tr -d ' ')" "10"
assert_contains "JSON alerts array"    "$json" '"alerts":["watchlist","suspicious_path"]'
json=$(run -u -a -p -j)
assert_eq "unix JSON lines are valid (quotes in path escaped)" "$(printf '%s\n' "$json" | valid_json_lines)" ""
assert_contains "unix JSON null path" "$json" '"path":null'

echo "Saved files (-f)"
assert_contains "decodes a saved tcp6 table" "$(run -f "$FIX/tcp6")" "[::1]:8080"
assert_contains "detects a saved udp table"  "$(run -f "$FIX/udp")" "udp"
assert_contains "detects a saved unix table" "$(run -f "$FIX/unix")" "/run/dbus/system_bus_socket"

echo "Output file"
run -o "$WORK/out.txt" >/dev/null
assert_contains "file written"            "$(cat "$WORK/out.txt")" "127.0.0.1:3306"
run -e -o "$WORK/out2.txt" >/dev/null
assert_not_contains "no colour codes in file" "$(cat "$WORK/out2.txt")" $'\033'

echo "Usage errors"
run -Z >/dev/null;              assert_eq "unknown option exit code" "$?" "2"
run -w /nonexistent >/dev/null; assert_eq "missing watchlist exit code" "$?" "2"
HEXTCP_NET_DIR="$WORK/empty" bash "$HEXTCP" >/dev/null 2>&1
assert_eq "missing tables exit code" "$?" "1"

echo "IPv6 decoding against Python's ipaddress (500 random addresses)"
python3 - "$WORK/rand6" "$WORK/expected" <<'PY'
import ipaddress, random, sys
random.seed(31431)
rows, expected = [], []
for i in range(500):
    groups = [random.choice([0, 0, 0, random.randrange(1, 0x10000)]) for _ in range(8)]
    b = ipaddress.IPv6Address(":".join(f"{g:x}" for g in groups)).packed
    hexaddr = "".join(b[j:j+4][::-1].hex().upper() for j in range(0, 16, 4))
    rows.append(f"  {i}: {hexaddr}:0050 {'0'*32}:0000 0A 0:0 0:0 0 0 0 {9000+i}")
    expected.append(str(ipaddress.IPv6Address(b)))
open(sys.argv[1], "w").write("  sl  local_address rem_address st\n" + "\n".join(rows) + "\n")
open(sys.argv[2], "w").write("\n".join(expected) + "\n")
PY
run -f "$WORK/rand6" -j | python3 -c 'import json,sys
[print(json.loads(l)["local_ip"]) for l in sys.stdin]' > "$WORK/actual"
if diff -q "$WORK/expected" "$WORK/actual" >/dev/null; then
  ok "all 500 match RFC 5952 formatting"
else
  bad "IPv6 decoding mismatch" "$(diff "$WORK/expected" "$WORK/actual" | head -4)"
fi

echo
echo "Passed: $PASS  Failed: $FAIL"
((FAIL == 0))
