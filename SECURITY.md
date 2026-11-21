# Security Policy

hextcp is often run as root during investigations, so problems in it are taken seriously and handled privately.

## Supported Versions

| Version | Supported |
|---|:--:|
| 2.x (`main`) | ✅ |
| 1.x | ❌ Decodes IPv6 addresses wrongly and emits invalid JSON. Please upgrade. |

## Scope

**In scope:**

- Command injection or code execution through socket paths, process names, watchlist files, saved tables (`-f`) or DNS responses
- Output that could mislead an investigation: wrongly decoded addresses, missed sockets, or alerts that fail to fire
- JSON output that can be broken or injected into by attacker-controlled values, such as a crafted Unix socket path

**Out of scope:**

- An attacker who already has root hiding sockets or processes from `/proc` (for example with a rootkit). hextcp reads what the kernel reports.
- Bugs in Bash, `find` or `getent` themselves

## Reporting a Vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub: open the repository's **Security** tab and select **Report a vulnerability**. If that isn't possible, email **stlwtrs@proton.me**.

Please include:

- The hextcp version (`hextcp -V`), distribution and Bash version
- Steps to reproduce, ideally with the raw `/proc/net` lines involved
- The impact: what an attacker gains or what hextcp gets wrong

## What to Expect

hextcp is maintained by one person, so responses are best effort:

- **Acknowledgement** within 7 days
- **A fix or documented mitigation** as soon as practical
- **Credit** in the changelog, unless you prefer to stay anonymous

Please allow reasonable time for a fix before public disclosure.
