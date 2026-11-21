# Contributing to hextcp

Thanks for your interest in hextcp. Bug reports, decoding edge cases and improvements are all welcome.

For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Reporting Bugs

Use the **Bug report** form in the Issues tab. If an address or state decodes wrongly, include the raw line from `/proc/net/tcp` (or `tcp6`, `udp`, `unix`) so it can be reproduced. Replace any addresses you don't want to make public.

## Pull Requests

1. Fork the repository and create a branch from `main`.
2. **Keep hextcp 100% native Bash.** No Python, `awk`, `sed`, `grep` or other external programs in the decoding, filtering or output path, because hextcp must work in restricted shells. The "Pure Bash guarantee" tests run it with an empty `PATH` and will fail if an external command slips in. External tools are only acceptable for optional features that Bash can't do natively (currently `-p`, `-e` and `-r`).
3. Add a fixture line and a test in `tests/run_tests.sh` for any new decoding, flag or output change.
4. Make sure everything passes:

   ```bash
   bash tests/run_tests.sh
   shellcheck -S warning hextcp.sh tests/run_tests.sh
   ```

5. Run `sudo ./hextcp.sh -a -p` on a real system.
6. Update `README.md` and `CHANGELOG.md` if usage or output changes.

## Code Style

- Quote every variable expansion (`"$var"`) unless word splitting is intended and commented.
- Two-space indentation.
- Comment the *why* behind anything involving byte order, kernel table formats or `/proc`.
- Keep JSON output valid: pass any value that could contain user-controlled text through `json_escape`.
- Don't break the JSON fields or exit codes without a major version bump and a changelog entry.
