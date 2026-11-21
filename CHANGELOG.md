# Changelog

All notable changes to hextcp are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-11-20

### Fixed
- **IPv6 decoding.** Each byte was converted to decimal and the results joined, so every IPv6 address was printed wrongly. Addresses are now decoded in hex and formatted per RFC 5952.
- **Invalid JSON.** Every TCP JSON line ended in `}}`, and Unix JSON with `-p` contained a stray `:`. Output is now valid JSON Lines, with strings escaped.
- **`-c` count.** It counted every line in the table regardless of filters, and printed table headers. It now prints only the number of matching sockets.
- **`-c` with `-u`** printed nothing.
- **Remote addresses in IPv6 mode** were decoded as IPv4, so IPv6 watchlist entries never matched.
- **Help on invalid options** exited with code 0.
- Color escape codes were written into `-o` output files.

### Changed
- **Default output shows IPv4 and IPv6 together.** Previously only IPv4 was shown, missing IPv6-only listeners. `-6` still selects IPv6 only, and the new `-4` selects IPv4 only.
- **Table layout:** a protocol column plus local and remote `address:port` columns, with widths that fit the data.
- **JSON fields:** `process` now holds the name and `pid` the number (previously combined as `"name pid"`). New fields: `family`, `remote_ip`, `remote_port`, `uid`, `inode` and `alerts`. `type`, `state`, `local_ip` and `local_port` are unchanged.
- **`-u` hides unnamed Unix sockets by default.** Use `-a` to show them.
- **Unix sockets** show their type (`STREAM`, `DGRAM`, `SEQPACKET`) and named states, including `LISTEN`.
- **`-e` implies `-p`** and also flags `/var/tmp` and `memfd` executables.
- **Reverse DNS** labels loopback and private ranges (including `172.16.0.0/12` and CGNAT `100.64.0.0/10`) instead of looking them up, and caches results.
- **Process mapping** builds an inode-to-PID table in one pass over `/proc` instead of searching once per socket, and no longer needs `lsof`.
- All decoding, filtering and output now use Bash builtins only (previously `awk`, `grep`, `cut`, `tail`, `wc`, `seq`, `tput` and `lsof`). Verified by tests that run with an empty `PATH`.

### Added
- `-U` for UDP sockets
- `-f <file>` to decode a saved copy of a socket table, with automatic TCP, UDP and Unix detection
- All 12 TCP state names
- Exit codes: `1` error, `2` usage error, `3` alert raised
- Watchlist comments (`#`), blank lines and case-insensitive IPv6 entries
- Process mapping fallback for systems without GNU `find`
- `-V` version flag; colour disabled automatically when output isn't a terminal or `NO_COLOR` is set
- Test suite (52 tests with fixture tables and a fake `/proc`) and GitHub Actions CI with ShellCheck

### Removed
- The decorative progress bar, which added a fixed delay and didn't reflect real progress

## [1.0.0] - 2026-11-04

### Added
- Initial release: decoded `/proc/net/tcp`, `tcp6` and `unix`, with process mapping, JSON output, a watchlist, suspicious-path highlighting, reverse DNS, counts and file output
