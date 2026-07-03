# exchange-recon

Non-destructive on-prem **Microsoft Exchange** reconnaissance & CVE triage — a single-file Python 3 tool that implements the *detection* portion of the classic Exchange attack methodology:

> Discover Exchange → Fingerprint version → Enumerate endpoints → Map weaknesses & CVEs.

It performs **no exploitation, no RCE, no writes, no password spraying and no logins**. The default run is passive recon + triage; an opt-in `--enum` mode does no-credential username harvesting (a checker — it never sends a password). Use it only against systems you are **explicitly authorized** to test.

> For what you can actually do with each finding, see **[CHEATSHEET.ru.md](CHEATSHEET.ru.md)** (Russian).

---

## Table of contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [Options](#options)
- [Output explained](#output-explained)
  - [Endpoints](#1-endpoints)
  - [Weaknesses / exposures](#2-weaknesses--exposures-non-cve)
  - [CVE assessment](#3-cve-assessment)
- [Modes: passive vs. active](#modes-passive-vs-active)
- [CVE coverage](#cve-coverage)
- [Verify requests are actually sent](#verify-requests-are-actually-sent)
- [Legal / authorized use](#legal--authorized-use)
- [License](#license)

---

## What it does

For each target it runs a fast, concurrent, non-destructive sweep and reports three things:

1. **Endpoint map** — probes the well-known Exchange virtual directories (`/owa/`, `/ecp/`, `/EWS/`, `/mapi/`, `/rpc/`, `/autodiscover/`, `/PowerShell/`, ActiveSync, …) and records status codes.
2. **Version + identity** — resolves the exact build (from `X-OWA-Version` or the `/owa/auth/<build>/` static path → product line), and extracts the **AD domain / hostname / OS** from a single unauthenticated NTLM negotiate (the same handshake Outlook/OWA sends).
3. **Findings**:
   - **Weaknesses / exposures** — non-CVE issues: info leaks, username-enumeration surface, password-spray surface, exposed ECP/PowerShell/ActiveSync, end-of-life software.
   - **CVE assessment** — split into **unauthenticated** and **requires-credentials** groups, each with a verdict, reasoning and OPSEC rating.

---

## Requirements

**None beyond Python 3.8+.** Pure standard library — no `pip install`, no virtualenv. Just drop the file and run.

> Note: unrelated tools you may have seen (e.g. `certat/exchange-scans`) need `requests`/`beautifulsoup4`. **This** tool does not.

---

## Install

```bash
# clone
git clone https://github.com/ushst/exchange-recon
cd exchange-recon

# or just grab the single file
curl -O https://raw.githubusercontent.com/ushst/exchange-recon/main/exchange_recon.py

chmod +x exchange_recon.py
```

---

## Quick start

```bash
# single host, passive (safe default)
python3 exchange_recon.py mail.corp.com

# add non-destructive active confirmation probes
python3 exchange_recon.py mail.corp.com --active

# many hosts from a file + JSON report, quiet console
python3 exchange_recon.py -f hosts.txt --active -j report.json -q

# watch every HTTP request being sent (proves traffic is real)
python3 exchange_recon.py mail.corp.com -v

# route through Burp/mitmproxy to inspect raw traffic
python3 exchange_recon.py mail.corp.com --proxy http://127.0.0.1:8080 --active

# username enumeration mode (no creds) — needs a user/email list
python3 exchange_recon.py mail.corp.com --enum -U users.txt --domain CORP
python3 exchange_recon.py mail.corp.com --enum -U emails.txt --enum-method autodiscover
```

`hosts.txt` is one target per line (`#` comments allowed); targets may be `host`, `host:port`, or `https://host`.

---

## Options

| Flag | Description |
|---|---|
| `target ...` | one or more hosts (positional) |
| `-f, --target-file` | file with one target per line |
| `-t, --timeout` | per-request timeout in seconds (default `8`) |
| `-w, --workers` | concurrent endpoint probes per host (default `8`) |
| `--active` | run **non-destructive** active confirmation probes (ProxyLogon SSRF, ProxyShell path-confusion) |
| `--enum` | separate no-cred username-harvest mode (needs `-U`); never sends a password |
| `-U, --userlist FILE` | users/emails to test, one per line (for `--enum`) |
| `--enum-method` | `auto` (default) / `autodiscover` / `timing` |
| `--domain` | AD/NetBIOS domain or UPN suffix to qualify bare usernames |
| `--enum-samples` | timing samples per user (default 3) |
| `-j, --json FILE` | write JSON report to `FILE` (`-` for stdout) |
| `--proxy URL` | send all traffic through an HTTP proxy |
| `--ua STRING` | override the User-Agent |
| `--verify-tls` | verify TLS certs (default **off** — self-signed is common on Exchange) |
| `-v, --verbose` | log every HTTP request (method, URL, status, timing) to stderr |
| `--no-color` | disable ANSI color |
| `-q, --quiet` | suppress the human report (JSON only) |

Run `python3 exchange_recon.py --help` for the built-in examples, verdict legend and notes.

---

## Output explained

### 1. Endpoints

Status of each probed virtual directory. `200/301/302` = reachable, `401/403` = auth-gated (still confirms it exists and is a valid enum/spray target), `---` = no response. NTLM endpoints additionally reveal the backend OS version.

### 2. Weaknesses / exposures (non-CVE)

The "misconfiguration / design-flaw" side of the methodology, derived **passively** from data already gathered (no extra traffic). Each finding has a **severity**, **evidence**, and a **methodology reference**:

| Finding | Severity | Meaning |
|---|---|---|
| `eol-product` | high | End-of-life Exchange in production — no vendor patches will ever ship |
| `ntlm-internal-disclosure` | medium | Internal AD domain / hostname / OS leaked via unauth NTLM |
| `user-enum-surface` | medium | Username enumeration possible (time-based NTLM + AutodiscoverV2), no creds |
| `password-spray-surface` | medium | Auth endpoints (OWA/EWS/EAS/Autodiscover) exposed for spraying |
| `ecp-exposed` | medium | ECP admin panel reachable |
| `powershell-exposed` | medium | Remote PowerShell endpoint reachable |
| `activesync-exposed` | low | ActiveSync exposed — potential MFA-bypass / spray vector |
| `version-disclosure` | low | Exact build disclosed pre-auth (aids precise CVE targeting) |
| `ews-ssrf-surface` | low | EWS present — SSRF-as-feature surface (Subscribe / CreateAttachmentFromUri) |

### 3. CVE assessment

Split into two blocks:

- **Unauthenticated** — flaws reachable/triageable with no credentials.
- **Requires valid credentials** — e.g. **ProxyNotShell (CVE-2022-41040)**. These are shown separately because **confirming** them needs a mailbox login. The tool does **not** authenticate or exploit; the verdict here is **version-based triage only**.

**Verdict legend:**

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | active probe positively confirmed the flaw (not exploited) |
| `LIKELY` | disclosed build is below the patched build **and** surface is reachable (or EOL product with no fix) |
| `CANDIDATE` | surface reachable but exact build not disclosed — verify manually |
| `ADVISORY` | client-side issue flagged because Exchange is present |
| `PATCHED` | build at/above the patched level, or active probe rejected |
| `N/A` | required attack surface not reachable |

Version gating compares the **(CU, SU)** build octets, so product lines with a static CU (e.g. Exchange 2013 = `15.0.1497.X`) are judged by the security-update level, not just the CU.

---

## Modes: passive vs. active

- **passive** (default): benign `GET`s + one unauthenticated NTLM Type-1 negotiate. CVE verdicts are inferred from build + reachable surface.
- **`--active`**: additionally sends **non-destructive** confirmation probes that positively prove an RCE-class flaw is present **without exploiting it**:
  - **ProxyLogon (CVE-2021-26855)** — triggers the SSRF and reads the reflected `x-calculatedbetarget` header. No webshell, no file write.
  - **ProxyShell (CVE-2021-34473)** — confirms the Autodiscover path-confusion via a `302` vs `400` status. No PowerShell/RCE stage is sent.

  A confirmed probe upgrades the verdict to `VULNERABLE` and overrides version-based guessing.

---

## Username enumeration mode (`--enum`)

A **separate, opt-in** mode that harvests valid usernames **without credentials**. It is a *checker* — it decides `valid` / `unknown` / `invalid` and **never sends a password or logs in**. Requires a user/email list (`-U`).

```bash
python3 exchange_recon.py mail.corp.com --enum -U users.txt --domain CORP
```

Two techniques (`--enum-method auto|autodiscover|timing`):

- **autodiscover** — `GET /autodiscover/autodiscover.json?Email=<u>` and compares the response to an invalid-user control (status / body / `X-BackEndCookie`). Quiet and precise; wants email format.
- **timing** — sends Basic auth `<principal>:<bogus-pass>` to an NTLM vdir and measures latency against a random-user baseline; valid users trend slower. Noisier; works with bare usernames + `--domain`.

Both are **heuristic and config-dependent** — confirm `valid` hits with a second method before spraying. What to do with the results is in [CHEATSHEET.ru.md](CHEATSHEET.ru.md#user-enum-surface).

Every non-CVE weakness in the normal report also prints a **`how-to:` hint** pointing at the relevant cheatsheet section.

---

## CVE coverage

| CVE | Name | Auth | Detection |
|---|---|---|---|
| CVE-2021-26855 | ProxyLogon (SSRF→RCE) | none | version + **active** SSRF probe |
| CVE-2021-34473 | ProxyShell (path confusion→RCE) | none | version + **active** path-confusion probe |
| CVE-2022-41040 | ProxyNotShell (SSRF→RCE) | **low-priv creds** | version-based only (separate block) |
| CVE-2024-21410 | NTLM relay to Exchange (EoP) | none (relay) | version + EOL reasoning |
| CVE-2023-23397 | Outlook zero-click NTLM leak | none | advisory (client-side) |
| CVE-2024-21413 | MonikerLink | none | advisory (client-side) |

---

## Verify requests are actually sent

Runs are fast (8 parallel workers over ~14 endpoints against a responsive server complete in well under a second). To see the traffic:

```bash
python3 exchange_recon.py mail.corp.com -v
```
```
  -> GET  https://mail.corp.com/owa/  ==> 200 (43 ms)
  -> GET  https://mail.corp.com/EWS/  ==> 401 (51 ms)
  -> GET  https://mail.corp.com/EWS/  ==> 401 (48 ms) [ntlm-negotiate]
  ...
[*] total HTTP requests sent: 18
```

Or point `--proxy` at Burp/mitmproxy to inspect full headers, bodies and the NTLM handshake.

---

## Legal / authorized use

This software is provided for **authorized security testing, education, and defensive research only**. Running it against systems you do not own or lack explicit written permission to test may be illegal. You are solely responsible for how you use it. The authors accept no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE).
