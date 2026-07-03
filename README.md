# exchange-recon

Non-destructive on-prem **Microsoft Exchange** reconnaissance & CVE triage — a single-file Python 3 tool that implements the *detection* portion of the classic Exchange attack methodology:

> Discover Exchange → Fingerprint version → Enumerate endpoints → Map CVEs.

It is **detection-only**. It performs no exploitation, no writes, no RCE, no password spraying and no user enumeration. Use it only against systems you are **explicitly authorized** to test.

## Features

- **Endpoint discovery** — probes the well-known Exchange virtual directories (`/owa/`, `/ecp/`, `/EWS/`, `/mapi/`, `/rpc/`, `/autodiscover/`, `/PowerShell/`, ActiveSync, …) and maps their status.
- **Version fingerprinting** — resolves the exact build from the `X-OWA-Version` header or the `/owa/auth/<build>/` static path, then maps it to the product line (Exchange 2013/2016/2019).
- **NTLM domain/host extraction** — sends a single benign NTLM Type-1 negotiate (the same handshake Outlook/OWA sends) and parses the Type-2 challenge for NetBIOS/DNS domain, hostname and OS version.
- **CVE triage** — reasons about exposure from build + reachable surface for ProxyLogon, ProxyShell, ProxyNotShell, CVE-2024-21410 (NTLM relay), and client-side advisories (CVE-2023-23397, CVE-2024-21413).
- **`--active` mode** — optional **non-destructive** confirmation probes that positively prove an RCE-class flaw is present *without exploiting it*:
  - **ProxyLogon (CVE-2021-26855)** — triggers the SSRF and reads the reflected `x-calculatedbetarget` header. No webshell, no file write.
  - **ProxyShell (CVE-2021-34473)** — confirms the Autodiscover path-confusion bypass via a `302` vs `400` status. No PowerShell/RCE stage is sent.
- **Output** — colored human-readable report + machine-readable JSON (`-j`).

## Requirements

**None beyond Python 3.8+.** Pure standard library — no `pip install`, no virtualenv. Just drop the file and run.

## Usage

```bash
# passive (default, safe)
python3 exchange_recon.py mail.target.com

# with non-destructive active confirmation probes
python3 exchange_recon.py mail.target.com --active

# multiple targets from a file + JSON report
python3 exchange_recon.py -f hosts.txt --active -j report.json

# through a proxy (e.g. Burp)
python3 exchange_recon.py mail.target.com --proxy http://127.0.0.1:8080
```

### Options

| Flag | Description |
|---|---|
| `-f, --target-file` | file with one target per line |
| `-t, --timeout` | per-request timeout (default 8s) |
| `-w, --workers` | concurrent endpoint probes per host (default 8) |
| `--active` | run non-destructive confirmation probes (ProxyLogon SSRF, ProxyShell path-confusion) |
| `-j, --json` | write JSON report to FILE (`-` for stdout) |
| `--proxy` | proxy URL |
| `--verify-tls` | verify TLS certs (default off — self-signed is common on Exchange) |
| `--no-color` | disable ANSI color |
| `-q, --quiet` | JSON only, suppress the human report |

## Verdicts

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | active probe positively confirmed the flaw (not exploited) |
| `LIKELY` | disclosed build is below the patched build **and** surface is reachable |
| `CANDIDATE` | surface reachable but exact build not disclosed — verify manually |
| `ADVISORY` | client-side issue flagged because Exchange is present |
| `PATCHED` | build at/above the patched level, or active probe rejected |
| `N/A` | required attack surface not reachable |

## Legal / authorized use

This software is provided for **authorized security testing, education, and defensive research only**. Running it against systems you do not own or have explicit written permission to test may be illegal. You are solely responsible for how you use it. The authors accept no liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
