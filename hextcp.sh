#!/usr/bin/env bash
#
# hextcp - decode the kernel's socket tables (/proc/net/tcp, tcp6, udp,
# udp6 and unix) into readable output, for systems where netstat, ss and
# lsof are missing or blocked.
#
# Copyright (c) 2026 Stlwtrs. Released under the MIT License.
#
# Unused fields from `read` are named so the column layout stays readable.
# shellcheck disable=SC2034

set -o pipefail

VERSION="2.0.0"

# Overridable for tests and for analysing a copy of another machine's /proc.
NET_DIR="${HEXTCP_NET_DIR:-/proc/net}"
PROC_DIR="${HEXTCP_PROC_DIR:-/proc}"

EXIT_OK=0
EXIT_ERROR=1
EXIT_USAGE=2
EXIT_ALERT=3

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

PROTO="tcp"        # tcp | udp | unix
FAMILY="both"      # 4 | 6 | both
SHOW_ALL=false
SHOW_PROC=false
COUNT_ONLY=false
JSON_OUT=false
CHECK_PATHS=false
RESOLVE_DNS=false
OUTPUT_FILE=""
WATCHLIST_FILE=""
INPUT_FILE=""

usage() {
  # read + printf instead of cat, so even --help needs nothing but Bash.
  local text
  IFS= read -r -d '' text <<'EOF'
Usage: hextcp [options]

Decode /proc/net socket tables without netstat, ss or lsof.

Tables (default: TCP, IPv4 and IPv6):
  -4            IPv4 only
  -6            IPv6 only
  -U            UDP instead of TCP
  -u            Unix domain sockets instead of TCP
  -f <file>     Decode a saved copy of a socket table (for example
                /proc/net/tcp copied from another machine)

Filtering and output:
  -a            Show every socket state, not just listening and connected
  -c            Print only the number of matching sockets
  -j            Output JSON Lines (one JSON object per socket)
  -o <file>     Also write the output to a file

Investigation:
  -p            Show the owning process and PID (root sees every process)
  -e            Flag processes running from /tmp, /var/tmp, /dev/shm, memory
                (memfd) or a deleted file (implies -p)
  -w <file>     Flag connections to IPs listed in a watchlist file
  -r            Resolve remote IPs to hostnames

  -V            Show version
  -h            Show this help

Exit codes: 0 success, 1 error, 2 usage error, 3 a watchlist or suspicious
path alert was raised.
EOF
  printf '%s' "$text"
}

die_usage() {
  printf 'hextcp: %s\n' "$1" >&2
  printf "Try 'hextcp -h' for help.\n" >&2
  exit "$EXIT_USAGE"
}

while getopts ":46Uuf:acjo:pew:rVh" opt; do
  case "$opt" in
    4) FAMILY="4" ;;
    6) FAMILY="6" ;;
    U) PROTO="udp" ;;
    u) PROTO="unix" ;;
    f) INPUT_FILE="$OPTARG" ;;
    a) SHOW_ALL=true ;;
    c) COUNT_ONLY=true ;;
    j) JSON_OUT=true ;;
    o) OUTPUT_FILE="$OPTARG" ;;
    p) SHOW_PROC=true ;;
    e) CHECK_PATHS=true; SHOW_PROC=true ;;
    w) WATCHLIST_FILE="$OPTARG" ;;
    r) RESOLVE_DNS=true ;;
    V) printf 'hextcp %s\n' "$VERSION"; exit "$EXIT_OK" ;;
    h) usage; exit "$EXIT_OK" ;;
    :) die_usage "option -$OPTARG needs an argument" ;;
    \?) die_usage "unknown option -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))
[[ $# -eq 0 ]] || die_usage "unexpected argument '$1'"

if [[ -n "$WATCHLIST_FILE" && ! -r "$WATCHLIST_FILE" ]]; then
  die_usage "cannot read watchlist '$WATCHLIST_FILE'"
fi
if [[ -n "$INPUT_FILE" && ! -r "$INPUT_FILE" ]]; then
  die_usage "cannot read input file '$INPUT_FILE'"
fi
if [[ -n "$INPUT_FILE" && "$SHOW_PROC" == true ]]; then
  printf 'hextcp: -p and -e need the live /proc of this machine; ignoring them for -f\n' >&2
  SHOW_PROC=false
  CHECK_PATHS=false
fi

# Colour only when writing to a terminal and NO_COLOR is not set.
if [[ -t 1 && -z "${NO_COLOR:-}" && "$JSON_OUT" == false ]]; then
  RED=$'\033[0;31m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'
else
  RED=""; YELLOW=""; NC=""
fi

# ---------------------------------------------------------------------------
# Decoding helpers
# ---------------------------------------------------------------------------

# TCP states from include/net/tcp_states.h
declare -A TCP_STATE=(
  [01]=ESTABLISHED [02]=SYN_SENT [03]=SYN_RECV [04]=FIN_WAIT1
  [05]=FIN_WAIT2 [06]=TIME_WAIT [07]=CLOSE [08]=CLOSE_WAIT
  [09]=LAST_ACK [0A]=LISTEN [0B]=CLOSING [0C]=NEW_SYN_RECV
)
# UDP reuses the same codes; an unconnected (listening) socket shows 07.
declare -A UDP_STATE=([01]=ESTABLISHED [07]=UNCONN)
declare -A UNIX_TYPE=([0001]=STREAM [0002]=DGRAM [0005]=SEQPACKET)
declare -A UNIX_STATE=([01]=UNCONNECTED [02]=CONNECTING [03]=CONNECTED [04]=DISCONNECTING)

# The kernel prints addresses as 32-bit words in host byte order. On
# little-endian machines (x86, most ARM) each word's bytes must be reversed.

decode_ipv4() {  # 0100007F -> 127.0.0.1
  local h="$1"
  printf -v REPLY '%d.%d.%d.%d' "0x${h:6:2}" "0x${h:4:2}" "0x${h:2:2}" "0x${h:0:2}"
}

decode_ipv6() {  # 32 hex digits -> compressed RFC 5952 text
  local h="$1" w i groups=() g
  for ((i = 0; i < 32; i += 8)); do
    w="${h:i:8}"
    w="${w:6:2}${w:4:2}${w:2:2}${w:0:2}"
    printf -v g '%x' "0x${w:0:4}"; groups+=("$g")
    printf -v g '%x' "0x${w:4:4}"; groups+=("$g")
  done

  # IPv4-mapped address, e.g. ::ffff:192.168.1.10
  if [[ "${groups[*]:0:5}" == "0 0 0 0 0" && "${groups[5]}" == "ffff" ]]; then
    printf -v REPLY '::ffff:%d.%d.%d.%d' \
      "$((0x${groups[6]} >> 8))" "$((0x${groups[6]} & 255))" \
      "$((0x${groups[7]} >> 8))" "$((0x${groups[7]} & 255))"
    return
  fi

  # Replace the longest run (2+ groups) of zero groups with "::".
  local best_start=-1 best_len=0 run_start=-1 run_len=0
  for ((i = 0; i < 8; i++)); do
    if [[ "${groups[i]}" == "0" ]]; then
      ((run_len == 0)) && run_start=$i
      ((run_len++))
      if ((run_len > best_len)); then best_len=$run_len; best_start=$run_start; fi
    else
      run_len=0
    fi
  done

  if ((best_len < 2)); then
    local IFS=":"; REPLY="${groups[*]}"
    return
  fi
  local left right
  left=$(IFS=":"; printf '%s' "${groups[*]:0:best_start}")
  right=$(IFS=":"; printf '%s' "${groups[*]:best_start+best_len}")
  REPLY="${left}::${right}"
}

decode_address() {  # HEX:PORT -> sets ADDR_IP, ADDR_PORT, ADDR_FAMILY
  local hex="${1%:*}" port="${1##*:}"
  if ((${#hex} == 32)); then
    decode_ipv6 "$hex"; ADDR_FAMILY="ipv6"
  else
    decode_ipv4 "$hex"; ADDR_FAMILY="ipv4"
  fi
  ADDR_IP="$REPLY"
  printf -v ADDR_PORT '%d' "0x$port"
}

format_endpoint() {  # ip port -> 1.2.3.4:80 or [::1]:80, port 0 shown as *
  local ip="$1" port="$2"
  ((port == 0)) && port="*"
  if [[ "$ip" == *:* ]]; then REPLY="[$ip]:$port"; else REPLY="$ip:$port"; fi
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
  REPLY="$s"
}

# ---------------------------------------------------------------------------
# Process mapping: one pass over /proc instead of one search per socket
# ---------------------------------------------------------------------------

declare -A SOCK_PID=() PID_NAME=() PID_EXE=()

build_socket_map() {
  local dir link pid inode fd
  if find "$PROC_DIR/self/fd" -maxdepth 0 -printf '' >/dev/null 2>&1; then
    # GNU find: print "fd-directory link-target" for every socket descriptor.
    while read -r dir link; do
      pid="${dir#"$PROC_DIR"/}"; pid="${pid%/fd}"
      inode="${link#socket:[}"; inode="${inode%]}"
      [[ -n "${SOCK_PID[$inode]:-}" ]] || SOCK_PID[$inode]="$pid"
    done < <(find "$PROC_DIR"/[0-9]*/fd -maxdepth 1 -type l -lname 'socket:*' -printf '%h %l\n' 2>/dev/null)
  else
    # Fallback for minimal systems (for example BusyBox find).
    for fd in "$PROC_DIR"/[0-9]*/fd/*; do
      link=$(readlink "$fd" 2>/dev/null) || continue
      [[ "$link" == socket:\[* ]] || continue
      pid="${fd#"$PROC_DIR"/}"; pid="${pid%%/*}"
      inode="${link#socket:[}"; inode="${inode%]}"
      [[ -n "${SOCK_PID[$inode]:-}" ]] || SOCK_PID[$inode]="$pid"
    done
  fi
}

lookup_process() {  # inode -> sets P_PID, P_NAME, P_EXE
  P_PID="${SOCK_PID[$1]:-}"; P_NAME=""; P_EXE=""
  [[ -n "$P_PID" ]] || return
  if [[ -z "${PID_NAME[$P_PID]+set}" ]]; then
    local name="?"
    read -r name < "$PROC_DIR/$P_PID/comm" 2>/dev/null
    PID_NAME[$P_PID]="$name"
    if [[ "$CHECK_PATHS" == true ]]; then
      PID_EXE[$P_PID]=$(readlink "$PROC_DIR/$P_PID/exe" 2>/dev/null)
    fi
  fi
  P_NAME="${PID_NAME[$P_PID]}"
  P_EXE="${PID_EXE[$P_PID]:-}"
}

is_suspicious_path() {
  [[ "$1" == /tmp/* || "$1" == /var/tmp/* || "$1" == /dev/shm/* \
    || "$1" == /memfd:* || "$1" == *" (deleted)" ]]
}

# ---------------------------------------------------------------------------
# Watchlist and DNS
# ---------------------------------------------------------------------------

declare -A WATCH=()

load_watchlist() {
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line//[[:space:]]/}"
    [[ -n "$line" ]] && WATCH["${line,,}"]=1
  done < "$WATCHLIST_FILE"
}

declare -A DNS_CACHE=()

resolve_host() {  # ip -> REPLY
  local ip="$1"
  case "$ip" in
    0.0.0.0|::) REPLY="-"; return ;;
    127.*|::1|::ffff:127.*) REPLY="[loopback]"; return ;;
    10.*|192.168.*|::ffff:10.*|::ffff:192.168.*|fe80:*|fc*|fd*) REPLY="[private]"; return ;;
  esac
  if [[ "$ip" =~ ^(::ffff:)?(172\.(1[6-9]|2[0-9]|3[01])|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7]))\. ]]; then
    REPLY="[private]"; return
  fi
  if [[ -z "${DNS_CACHE[$ip]+set}" ]]; then
    local host=""
    read -r _ host _ < <(getent hosts "$ip" 2>/dev/null)
    DNS_CACHE[$ip]="${host:-[no DNS]}"
  fi
  REPLY="${DNS_CACHE[$ip]}"
}

# ---------------------------------------------------------------------------
# Collect rows
# ---------------------------------------------------------------------------

ROWS_JSON=()
COL_PROTO=(); COL_STATE=(); COL_LOCAL=(); COL_REMOTE=(); COL_HOST=(); COL_PROC=(); COL_FLAGS=()
ALERTS=0

add_row() {  # proto state local remote host proc flags json
  COL_PROTO+=("$1"); COL_STATE+=("$2"); COL_LOCAL+=("$3"); COL_REMOTE+=("$4")
  COL_HOST+=("$5"); COL_PROC+=("$6"); COL_FLAGS+=("$7"); ROWS_JSON+=("$8")
}

parse_inet_table() {  # file proto
  local file="$1" proto="$2" header
  local sl local_addr rem_addr st _txrx _trtm _retr uid _timeout inode _rest
  local state lip lport lfam rip rport flags host proc json alerts esc_name esc_exe
  {
    read -r header
    while read -r sl local_addr rem_addr st _txrx _trtm _retr uid _timeout inode _rest; do
      [[ -n "$local_addr" ]] || continue

      if [[ "$proto" == "udp" ]]; then state="${UDP_STATE[$st]:-$st}"; else state="${TCP_STATE[$st]:-$st}"; fi
      if [[ "$SHOW_ALL" == false ]]; then
        case "$state" in LISTEN|ESTABLISHED|UNCONN) ;; *) continue ;; esac
      fi

      decode_address "$local_addr"; lip="$ADDR_IP"; lport="$ADDR_PORT"; lfam="$ADDR_FAMILY"
      case "$FAMILY" in
        4) [[ "$lfam" == ipv4 ]] || continue ;;
        6) [[ "$lfam" == ipv6 ]] || continue ;;
      esac
      decode_address "$rem_addr"; rip="$ADDR_IP"; rport="$ADDR_PORT"

      flags=""; alerts=""; host=""; proc=""
      P_PID=""; P_NAME=""; P_EXE=""
      if [[ ${#WATCH[@]} -gt 0 && -n "${WATCH[${rip,,}]:-}" ]]; then
        flags+="[!] WATCHLIST "; alerts+='"watchlist",'
      fi
      if [[ "$SHOW_PROC" == true && "$inode" != "0" ]]; then
        lookup_process "$inode"
        [[ -n "$P_PID" ]] && proc="$P_NAME ($P_PID)"
        if [[ "$CHECK_PATHS" == true && -n "$P_EXE" ]] && is_suspicious_path "$P_EXE"; then
          flags+="[!] SUSPICIOUS PATH "; alerts+='"suspicious_path",'
        fi
      fi
      [[ -n "$alerts" ]] && ((ALERTS++))
      if [[ "$RESOLVE_DNS" == true ]]; then resolve_host "$rip"; host="$REPLY"; fi

      if [[ "$JSON_OUT" == true ]]; then
        json_escape "$P_NAME"; esc_name="$REPLY"
        json_escape "$P_EXE"; esc_exe="$REPLY"
        json="{\"type\":\"$proto\",\"family\":\"$lfam\",\"state\":\"$state\""
        json+=",\"local_ip\":\"$lip\",\"local_port\":$lport"
        json+=",\"remote_ip\":\"$rip\",\"remote_port\":$rport"
        json+=",\"uid\":$uid,\"inode\":$inode"
        if [[ "$SHOW_PROC" == true ]]; then
          json+=",\"pid\":${P_PID:-null},\"process\":"
          [[ -n "$P_PID" ]] && json+="\"$esc_name\"" || json+="null"
          [[ "$CHECK_PATHS" == true ]] && { [[ -n "$P_EXE" ]] && json+=",\"exe\":\"$esc_exe\"" || json+=",\"exe\":null"; }
        fi
        [[ "$RESOLVE_DNS" == true ]] && { json_escape "$host"; json+=",\"remote_host\":\"$REPLY\""; }
        json+=",\"alerts\":[${alerts%,}]}"
      fi

      format_endpoint "$lip" "$lport"; local lep="$REPLY"
      format_endpoint "$rip" "$rport"; local rep="$REPLY"
      [[ "$lfam" == ipv6 ]] && proto_label="${proto}6" || proto_label="$proto"
      add_row "$proto_label" "$state" "$lep" "$rep" "$host" "$proc" "${flags% }" "$json"
    done
  } < "$file"
}

parse_unix_table() {  # file
  local file="$1" header
  local _num _ref _proto uflags utype st inode path state stype proc json alerts esc
  {
    read -r header
    while read -r _num _ref _proto uflags utype st inode path; do
      [[ -n "$inode" ]] || continue
      [[ "$SHOW_ALL" == false && -z "$path" ]] && continue

      stype="${UNIX_TYPE[$utype]:-$utype}"
      # __SO_ACCEPTCON (0x10000) in the flags field marks a listening socket.
      if (( (0x$uflags & 0x10000) != 0 )); then state="LISTEN"; else state="${UNIX_STATE[$st]:-$st}"; fi

      proc=""; alerts=""; P_PID=""; P_NAME=""; P_EXE=""
      if [[ "$SHOW_PROC" == true ]]; then
        lookup_process "$inode"
        [[ -n "$P_PID" ]] && proc="$P_NAME ($P_PID)"
        if [[ "$CHECK_PATHS" == true && -n "$P_EXE" ]] && is_suspicious_path "$P_EXE"; then
          alerts='"suspicious_path"'; ((ALERTS++))
        fi
      fi

      if [[ "$JSON_OUT" == true ]]; then
        json_escape "$path"; esc="$REPLY"
        json="{\"type\":\"unix\",\"socket_type\":\"$stype\",\"state\":\"$state\",\"inode\":$inode"
        if [[ -n "$path" ]]; then json+=",\"path\":\"$esc\""; else json+=",\"path\":null"; fi
        if [[ "$SHOW_PROC" == true ]]; then
          json_escape "$P_NAME"
          json+=",\"pid\":${P_PID:-null},\"process\":"
          [[ -n "$P_PID" ]] && json+="\"$REPLY\"" || json+="null"
        fi
        json+=",\"alerts\":[${alerts}]}"
      fi

      [[ -n "$alerts" ]] && flag="[!] SUSPICIOUS PATH" || flag=""
      add_row "$stype" "$state" "${path:-(unnamed)}" "" "" "$proc" "$flag" "$json"
    done
  } < "$file"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

[[ -n "$WATCHLIST_FILE" ]] && load_watchlist

if [[ "$SHOW_PROC" == true ]]; then
  if [[ $EUID -ne 0 ]]; then
    printf 'hextcp: not running as root; only your own processes can be mapped\n' >&2
  fi
  build_socket_map
fi

if [[ -n "$INPUT_FILE" ]]; then
  read -r first_line < "$INPUT_FILE" || true
  if [[ "$first_line" == *Inode*Path* ]]; then
    PROTO="unix"
  elif [[ "$PROTO" != "unix" && "$first_line" == *drops* ]]; then
    PROTO="udp"
  fi
  if [[ "$PROTO" == "unix" ]]; then parse_unix_table "$INPUT_FILE"; else parse_inet_table "$INPUT_FILE" "$PROTO"; fi
else
  tables=()
  if [[ "$PROTO" == "unix" ]]; then
    tables=("$NET_DIR/unix")
  else
    [[ "$FAMILY" != "6" ]] && tables+=("$NET_DIR/$PROTO")
    [[ "$FAMILY" != "4" ]] && tables+=("$NET_DIR/${PROTO}6")
  fi

  found=0
  for t in "${tables[@]}"; do
    [[ -r "$t" ]] || continue
    found=1
    if [[ "$PROTO" == "unix" ]]; then parse_unix_table "$t"; else parse_inet_table "$t" "$PROTO"; fi
  done
  if ((found == 0)); then
    printf 'hextcp: cannot read %s (not Linux, or IPv6 disabled?)\n' "${tables[*]}" >&2
    exit "$EXIT_ERROR"
  fi
fi

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

emit() {  # plain-line [colour]
  printf '%s%s%s\n' "${2:-}" "$1" "${2:+$NC}"
  [[ -n "$OUTPUT_FILE" ]] && printf '%s\n' "$1" >> "$OUTPUT_FILE"
  return 0
}

[[ -n "$OUTPUT_FILE" ]] && : > "$OUTPUT_FILE"

total=${#COL_STATE[@]}

if [[ "$COUNT_ONLY" == true ]]; then
  emit "$total"
elif [[ "$JSON_OUT" == true ]]; then
  for row in "${ROWS_JSON[@]}"; do emit "$row"; done
else
  # Work out column widths, then print an aligned table.
  show_remote=true; [[ "$PROTO" == "unix" ]] && show_remote=false
  headers=("PROTO" "STATE" "LOCAL ADDRESS")
  [[ "$PROTO" == "unix" ]] && headers=("TYPE" "STATE" "PATH")
  w_proto=${#headers[0]}; w_state=${#headers[1]}; w_local=${#headers[2]}; w_remote=14; w_host=11; w_proc=7
  for ((i = 0; i < total; i++)); do
    ((${#COL_PROTO[i]} > w_proto)) && w_proto=${#COL_PROTO[i]}
    ((${#COL_STATE[i]} > w_state)) && w_state=${#COL_STATE[i]}
    ((${#COL_LOCAL[i]} > w_local)) && w_local=${#COL_LOCAL[i]}
    ((${#COL_REMOTE[i]} > w_remote)) && w_remote=${#COL_REMOTE[i]}
    ((${#COL_HOST[i]} > w_host)) && w_host=${#COL_HOST[i]}
    ((${#COL_PROC[i]} > w_proc)) && w_proc=${#COL_PROC[i]}
  done

  build_line() {  # proto state local remote host proc flags
    local line
    printf -v line '%-*s  %-*s  %-*s' "$w_proto" "$1" "$w_state" "$2" "$w_local" "$3"
    [[ "$show_remote" == true ]] && printf -v line '%s  %-*s' "$line" "$w_remote" "$4"
    [[ "$RESOLVE_DNS" == true ]] && printf -v line '%s  %-*s' "$line" "$w_host" "$5"
    [[ "$SHOW_PROC" == true ]] && printf -v line '%s  %-*s' "$line" "$w_proc" "$6"
    [[ -n "$7" ]] && line+="  $7"
    REPLY="${line%"${line##*[![:space:]]}"}"
  }

  if [[ -t 1 && -z "$OUTPUT_FILE" ]]; then
    printf 'hextcp %s - decoded %s\n\n' "$VERSION" "${INPUT_FILE:-$NET_DIR}" >&2
  fi
  build_line "${headers[0]}" "${headers[1]}" "${headers[2]}" "REMOTE ADDRESS" "REMOTE HOST" "PROCESS" ""
  emit "$REPLY"
  for ((i = 0; i < total; i++)); do
    build_line "${COL_PROTO[i]}" "${COL_STATE[i]}" "${COL_LOCAL[i]}" "${COL_REMOTE[i]}" \
      "${COL_HOST[i]}" "${COL_PROC[i]}" "${COL_FLAGS[i]}"
    colour=""
    [[ "${COL_FLAGS[i]}" == *WATCHLIST* ]] && colour="$RED"
    [[ -z "$colour" && -n "${COL_FLAGS[i]}" ]] && colour="$YELLOW"
    emit "$REPLY" "$colour"
  done
  [[ -n "$OUTPUT_FILE" ]] && printf '\nSaved %d socket(s) to %s\n' "$total" "$OUTPUT_FILE" >&2
fi

((ALERTS > 0)) && exit "$EXIT_ALERT"
exit "$EXIT_OK"
