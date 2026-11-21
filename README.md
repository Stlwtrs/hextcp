```
      :::    ::: :::::::::: :::    ::: ::::::::::: ::::::::  :::::::::
     :+:    :+: :+:        :+:    :+:     :+:    :+:    :+: :+:    :+:
    +:+    +:+ +:+         +:+  +:+      +:+    +:+        +:+    +:+
   +#++:++#++ +#++:++#     +#++:+       +#+    +#+        +#++:++#+
  +#+    +#+ +#+         +#+  +#+      +#+    +#+        +#+
 #+#    #+# #+#        #+#    #+#     #+#    #+#    #+# #+#
###    ### ########## ###    ###     ###     ########  ###
```

**Decode Linux socket tables straight from `/proc/net`, for systems where `netstat`, `ss` and `lsof` are missing or blocked.**

![Tests](https://github.com/Stlwtrs/hextcp/actions/workflows/tests.yml/badge.svg)
![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Bash](https://img.shields.io/badge/bash-4.0%2B-4EAA25?logo=gnubash&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Table of Contents

1. [Why hextcp Exists](#why-hextcp-exists)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Examples](#examples)
6. [How It Works](#how-it-works)
7. [What Changed in Version 2](#what-changed-in-version-2)
8. [Limitations](#limitations)
9. [Testing](#testing)
10. [Contributing and Security](#contributing-and-security)
11. [How This Was Built](#how-this-was-built)
12. [License and Disclaimer](#license-and-disclaimer)

---

## Why hextcp Exists

During Linux privilege escalation, for example in TryHackMe's *Red Stone One Carat* room, you often land in a restricted shell where `netstat`, `ss` and `lsof` are blocked or not installed. The kernel still exposes every socket in `/proc/net/tcp`, but as raw little-endian hexadecimal:

```text
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001
```

Decoding that by hand during a CTF is slow and error-prone. hextcp turns it into this:

```text
PROTO  STATE   LOCAL ADDRESS   REMOTE ADDRESS
tcp    LISTEN  127.0.0.1:3306  0.0.0.0:*
```

A MySQL server reachable only from the machine itself: a classic privilege-escalation lead.

---

## Features

| Feature | Flag |
|---|---|
| TCP over IPv4 and IPv6 together, with correct RFC 5952 IPv6 formatting | default, `-4`, `-6` |
| UDP sockets | `-U` |
| Unix domain sockets, including abstract (`@name`) sockets | `-u` |
| Local **and** remote address and port for every connection | default |
| All 12 TCP states by name (`TIME_WAIT`, `CLOSE_WAIT`, ...) | `-a` |
| Owning process and PID, found in one pass over `/proc` | `-p` |
| Flag processes running from `/tmp`, `/var/tmp`, `/dev/shm`, memory (`memfd`) or a deleted file | `-e` |
| Flag connections to IPs in a threat watchlist (IPv4 and IPv6) | `-w <file>` |
| Reverse DNS, with private and loopback ranges labelled instead of looked up | `-r` |
| Valid JSON Lines output for `jq`, scripts and SIEMs | `-j` |
| Decode a **saved copy** of a table from another machine | `-f <file>` |
| Count matching sockets, or save output to a file | `-c`, `-o <file>` |
| Scriptable exit codes, including `3` when an alert fires | |

**100% native Bash for decoding.** Reading and decoding every table, filtering, counting, JSON, watchlist checks, saved files and output use only Bash builtins, with no Python, `awk`, `sed`, `grep` or even `cat`. The test suite proves it by running hextcp with an empty `PATH`, so no external programs exist at all. That's what makes it usable in restricted shells.

Only three optional flags need anything outside Bash, because Bash has no builtin to read symlinks or query DNS:

| Flag | Needs | Why |
|---|---|---|
| `-p`, `-e` | `find` or `readlink` | Reading `/proc/<pid>/fd` links to map sockets to processes. Falls back from `find` to `readlink` on BusyBox systems |
| `-r` | `getent` | Reverse DNS lookups |

---

## Installation

```bash
git clone https://github.com/Stlwtrs/hextcp.git
cd hextcp
sudo install -Dm755 hextcp.sh /usr/local/bin/hextcp
```

Or run it in place with `./hextcp.sh`. On a target machine with no `git`, the script is a single file you can copy over and run with `bash hextcp.sh`.

---

## Usage

```text
hextcp [-46Uu] [-acjpre] [-f file] [-o file] [-w file] [-V] [-h]
```

| Flag | Description |
|---|---|
| `-4` / `-6` | IPv4 or IPv6 only (default: both) |
| `-U` | UDP instead of TCP |
| `-u` | Unix domain sockets instead of TCP |
| `-f <file>` | Decode a saved table; the type is detected from its header |
| `-a` | Show every state (default: listening and connected only; for Unix sockets, named sockets only) |
| `-c` | Print only the number of matching sockets |
| `-j` | JSON Lines output |
| `-o <file>` | Also write the output to a file (without colour codes) |
| `-p` | Show the owning process and PID. Without root, only your own processes are visible |
| `-e` | Flag suspicious executable paths (implies `-p`) |
| `-w <file>` | Flag connections to watchlisted IPs: one per line, `#` comments allowed |
| `-r` | Resolve remote IPs to hostnames |
| `-V` / `-h` | Version / help |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | No socket table could be read |
| `2` | Usage error |
| `3` | A watchlist or suspicious-path alert was raised |

---

## Examples

Outputs below come from the test fixtures in `tests/fixtures/`, so they are reproducible.

**Everything listening or connected, IPv4 and IPv6** (`hextcp`)

```text
PROTO  STATE        LOCAL ADDRESS                  REMOTE ADDRESS
tcp    LISTEN       127.0.0.1:3306                 0.0.0.0:*
tcp    ESTABLISHED  10.0.2.15:22                   192.168.1.100:54321
tcp    ESTABLISHED  10.0.2.15:45296                13.12.11.10:4444
tcp6   LISTEN       [::]:80                        [::]:*
tcp6   LISTEN       [::1]:8080                     [::]:*
tcp6   ESTABLISHED  [::ffff:10.0.2.15]:22          [::ffff:192.168.1.100]:54322
tcp6   LISTEN       [fe80::25a:50ff:fe12:3456]:53  [::]:*
tcp6   ESTABLISHED  [2001:db8::1]:443              [2001:db8:0:1::abcd]:60000
tcp6   LISTEN       [2001:db8::1:0:0:1]:9000       [::]:*
```

**Replicate `netstat -tulpn`**

```bash
sudo hextcp -a -p        # TCP
sudo hextcp -U -p        # UDP
```

**Threat hunting: watchlisted IPs and suspicious processes**

```bash
hextcp -w watchlist.txt          # connections to known-bad IPs
sudo hextcp -p -e                # processes running from suspicious locations
```

Watchlist output, with unflagged rows omitted:

```text
PROTO  STATE        LOCAL ADDRESS                  REMOTE ADDRESS
tcp    ESTABLISHED  10.0.2.15:45296                13.12.11.10:4444              [!] WATCHLIST
tcp6   ESTABLISHED  [2001:db8::1]:443              [2001:db8:0:1::abcd]:60000    [!] WATCHLIST
```

Rows are highlighted red for watchlist hits and yellow for suspicious paths, and the exit code is `3`, so the check works in scripts and cron jobs:

```bash
sudo hextcp -e -w watchlist.txt -c >/dev/null || echo "hextcp raised an alert"
```

**Decode a table from a restricted shell on another machine**

When you can only run `cat` on the target, copy the raw table back and decode it locally:

```bash
# on the target
cat /proc/net/tcp
# on your machine, paste it into a file, then:
hextcp -f target_tcp.txt
```

**JSON for `jq` and log pipelines**

```bash
hextcp -j | jq 'select(.state == "LISTEN") | .local_port'
```

```json
{"type":"tcp","family":"ipv4","state":"LISTEN","local_ip":"127.0.0.1","local_port":3306,"remote_ip":"0.0.0.0","remote_port":0,"uid":0,"inode":1001,"alerts":[]}
```

**Unix sockets** (`hextcp -u`)

```text
TYPE    STATE        PATH
STREAM  LISTEN       /run/dbus/system_bus_socket
DGRAM   UNCONNECTED  @abstract-name
```

---

## How It Works

1. **Read the table** line by line with Bash's `read`, which splits the columns without any external program.
2. **Decode addresses.** The kernel prints each address as 32-bit words in the machine's byte order. hextcp reverses the bytes of each word, then formats IPv4 as dotted decimal and IPv6 in standard compressed form (RFC 5952: lowercase, longest zero run replaced by `::`, IPv4-mapped addresses shown as `::ffff:a.b.c.d`).
3. **Decode ports and states.** Ports use Bash's hex arithmetic (`0x0CEA` becomes `3306`). State codes map to names from the kernel's `tcp_states.h`.
4. **Map sockets to processes** (`-p`). Each socket has an inode number. hextcp scans every `/proc/<pid>/fd` link **once** and builds an inode-to-PID table, instead of searching `/proc` again for every socket.
5. **Raise alerts.** Remote IPs are checked against the watchlist, loaded once into a lookup table. With `-e`, each process's `/proc/<pid>/exe` link is checked for suspicious locations.

---

## What Changed in Version 2

Version 2 started as a review of version 1 and found several real decoding bugs:

| Version 1 | Problem | Version 2 |
|---|---|---|
| IPv6 bytes converted to decimal and joined | Every IPv6 address was wrong. `::ffff:127.0.0.1` printed as `0000::0000::0025:5255:1270:01` | Correct RFC 5952 output, verified against Python's `ipaddress` on 500 random addresses |
| JSON lines ended in `}}`, and `-u -p -j` had a stray `:` | Every JSON line was invalid, so `jq` rejected it | Valid JSON Lines with escaped strings, verified in tests |
| `-c` counted every line in the file | Ignored the state filter, and printed table headers | Counts only matching sockets |
| No remote address column | Couldn't see who a connection was talking to | Local and remote address and port on every row |
| Default showed IPv4 only | Missed services listening only on IPv6 | IPv4 and IPv6 together by default |
| `find` over `/proc` once per socket | Very slow on busy systems | One pass builds an inode lookup table |
| Watchlist compared IPv4 decoding of IPv6 addresses | IPv6 watchlist entries never matched | Works for both families, case-insensitive |
| Decorative progress bar | Added a fixed delay and didn't reflect real progress | Removed |

Full details are in [CHANGELOG.md](CHANGELOG.md), including the JSON and default-output changes that affect existing scripts.

---

## Limitations

- **Linux only,** and **Bash 4.0 or newer** (for associative arrays).
- **Little-endian byte order assumed.** Correct on x86 and almost all ARM systems. Tables from big-endian machines (some MIPS, s390x) will decode wrongly.
- **A snapshot, not a monitor.** Short-lived connections that open and close between runs are not seen.
- **Process mapping needs root** to see other users' processes, and doesn't work with `-f`, since a saved table has no `/proc` to match against.
- **The suspicious-path check is a heuristic.** Legitimate software sometimes runs from `/tmp` or `memfd`, and a careful attacker avoids these locations. Treat a flag as a lead, not proof.
- **Name resolution can leak.** `-r` sends DNS queries for remote IPs, which may be visible to whoever controls the resolver. Don't use it when that matters.

---

## Testing

```bash
bash tests/run_tests.sh
```

52 tests run hextcp against fixture tables and a fake `/proc` tree, so results are identical on every machine. They cover IPv4 and IPv6 decoding (including 500 random IPv6 addresses compared with Python's `ipaddress` module), the pure-Bash guarantee (running with an empty `PATH`), state filtering, counts, UDP and Unix sockets, process mapping (including the BusyBox fallback), watchlist and suspicious-path alerts, JSON validity, saved-file detection, output files and exit codes.

GitHub Actions runs the tests and ShellCheck on every push, then runs hextcp against the build machine's real socket tables.

The test suite itself uses Python, to validate JSON and to cross-check IPv6 decoding against an independent implementation. That only runs on a development machine or in CI. hextcp never needs Python on the system you're investigating.

---

## Contributing and Security

Bug reports and improvements are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). For security issues, follow [SECURITY.md](SECURITY.md).

---

## How This Was Built

I built version 1 myself while working through TryHackMe rooms. Version 2 was reworked with assistance from Claude (Anthropic's AI assistant) after a review of version 1 found the decoding bugs above. I reviewed the changes and verified them with the test suite and on my own system before release.

---

## License and Disclaimer

Released under the [MIT License](LICENSE).

hextcp is intended for education, CTFs, incident response and authorized security testing. Only enumerate systems you own or have explicit permission to test.
