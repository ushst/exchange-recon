#!/usr/bin/env python3
"""
exchange_recon.py — Non-destructive on-prem Microsoft Exchange recon & CVE triage.

Implements the *detection* portion of the MS Exchange Pentesting methodology:
  Discover Exchange -> Fingerprint version -> Enumerate endpoints -> Map CVEs.

This tool is DETECTION-ONLY. It performs no exploitation, no writes, no RCE,
no password spraying, no user enumeration.

Two modes:
  * passive (default): benign GET + a single unauthenticated NTLM Type-1
    negotiate (the same handshake a normal Outlook/OWA client sends). CVE
    verdicts are inferred from disclosed build + reachable attack surface.
  * --active: additionally sends NON-DESTRUCTIVE confirmation probes that
    positively prove an RCE-class flaw is present WITHOUT exploiting it —
    e.g. ProxyLogon (CVE-2021-26855) SSRF triggers a benign backend proxy
    and we read the reflected header; ProxyShell (CVE-2021-34473) path
    confusion is confirmed by a 302 vs 400 status. No webshell is dropped,
    no command is executed, no mailbox/file is written.

Use only against systems you are authorized to test.

Author: generated for authorized security testing.
License: MIT
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import dataclasses
import json
import re
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Iterable, Optional

__version__ = "1.0.0"

# A pre-computed NTLM Type-1 (NEGOTIATE) message. Same one a normal client sends.
NTLM_TYPE1 = (
    "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="
)

# Known Exchange virtual directories worth probing. NTLM ones are used for
# version/domain fingerprinting; the rest just get status/redirect mapping.
EXCHANGE_ENDPOINTS = [
    ("/autodiscover/autodiscover.xml", True),
    ("/EWS/Exchange.asmx", True),
    ("/EWS/", True),
    ("/mapi/", True),
    ("/mapi/emsmdb/", True),
    ("/rpc/", True),
    ("/OAB/", True),
    ("/Microsoft-Server-ActiveSync", True),
    ("/PowerShell/", True),
    ("/owa/", False),
    ("/owa/auth/logon.aspx", False),
    ("/ecp/", False),
    ("/ecp/Current/exporttool/"
     "microsoft.exchange.ediscovery.exporttool.application", False),
    ("/aspnet_client/", False),
]

# Endpoints that speak NTLM — these enable unauthenticated, time-based
# username enumeration (valid users respond measurably slower).
NTLM_ENDPOINTS = {p for p, ntlm in EXCHANGE_ENDPOINTS if ntlm}

# ---------------------------------------------------------------------------
# Exchange build -> (product, cumulative update) table.
# Not exhaustive; covers builds relevant to modern CVE triage. The minor build
# number monotonically increases, so range comparisons decide patch state.
# Keyed by (major, minor) i.e. 15.2 = Exchange 2019, 15.1 = 2016, 15.0 = 2013.
# ---------------------------------------------------------------------------
PRODUCT_BY_MAJORMINOR = {
    (15, 2): "Exchange Server 2019",
    (15, 1): "Exchange Server 2016",
    (15, 0): "Exchange Server 2013",
    (14, 3): "Exchange Server 2010 SP3",
    (8, 3): "Exchange Server 2007",
}

# Products past end-of-support: no vendor patches ship for CVEs disclosed after
# their EOL date, so a CVE simply "not listing" them does NOT mean safe — it
# usually means permanently exposed. (2013: 2023-04-11, 2010: 2020-10-13,
# 2007: 2017-04-11.)
EOL_PRODUCTS = {
    "Exchange Server 2013",
    "Exchange Server 2010 SP3",
    "Exchange Server 2007",
}

# ---------------------------------------------------------------------------
# CVE knowledge base. Each entry describes how we *infer* exposure. Because this
# is a non-destructive scanner we do version/exposure reasoning, not live PoC.
#
# fixed_build: the third build octet ("15.2.<X>.<Y>") at/above which the issue
# is patched for that product line. A value of None means "no version gate —
# report as candidate if the surface is present".
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class CVE:
    cve: str
    name: str
    impact: str
    auth: str
    # product-line -> minimum patched build. Value is either the 3rd octet
    # (CU-level gate, e.g. 1118) or a (3rd, 4th) tuple for SU-level gates where
    # the CU number is static and only the SU moves (e.g. 2013 = 15.0.1497.X,
    # so (1497, 44)). Missing line => not in this CVE's affected product list.
    fixed: dict
    # endpoints whose presence indicates the attack surface exists
    surface: list
    opsec: str
    notes: str = ""
    # name of an active, NON-DESTRUCTIVE probe method on ExchangeRecon that can
    # positively confirm the flaw without exploitation. None => version-only.
    active_check: Optional[str] = None


CVE_DB: list[CVE] = [
    CVE(
        cve="CVE-2021-26855",
        name="ProxyLogon (SSRF)",
        impact="Pre-auth SSRF -> chained RCE (CVE-2021-27065 write)",
        auth="None",
        fixed={"Exchange Server 2019": 858, "Exchange Server 2016": 2176,
               "Exchange Server 2013": (1497, 12)},
        surface=["/owa/", "/ecp/", "/autodiscover/autodiscover.xml"],
        opsec="high",
        notes="Actively exploited 2021. Version-gate below CU + March 2021 patch.",
        active_check="active_proxylogon_ssrf",
    ),
    CVE(
        cve="CVE-2021-34473",
        name="ProxyShell (path confusion)",
        impact="Pre-auth RCE via ACL bypass + PowerShell EoP",
        auth="None",
        fixed={"Exchange Server 2019": 922, "Exchange Server 2016": 2308,
               "Exchange Server 2013": (1497, 15)},
        surface=["/autodiscover/autodiscover.json", "/owa/", "/PowerShell/"],
        opsec="high",
        notes="Requires Autodiscover + PowerShell backend reachable.",
        active_check="active_proxyshell_pathconfusion",
    ),
    CVE(
        cve="CVE-2022-41040",
        name="ProxyNotShell (SSRF)",
        impact="Auth SSRF -> RCE (chained with CVE-2022-41082)",
        auth="Low-priv creds",
        fixed={"Exchange Server 2019": 1118, "Exchange Server 2016": (2507, 16),
               "Exchange Server 2013": (1497, 44)},
        surface=["/autodiscover/autodiscover.json", "/PowerShell/"],
        opsec="medium",
        notes="Nov 2022 patch. 2013 gated by SU (15.0.1497.44); needs valid "
              "mailbox creds to exploit — detection is version-based only.",
    ),
    CVE(
        cve="CVE-2023-23397",
        name="Outlook zero-click NTLM leak",
        impact="Zero-click NTLM hash theft via calendar reminder",
        auth="None",
        fixed={},  # client-side; surfaced as advisory, not host-version gated
        surface=[],
        opsec="low",
        notes="Client-side Outlook flaw. Reported as advisory when Exchange is present.",
    ),
    CVE(
        cve="CVE-2024-21410",
        name="NTLM relay to Exchange",
        impact="Relay captured NTLMv2 -> Exchange, no crack needed",
        auth="None (relay)",
        # 2019 CU14 (15.2.1544.4) & 2016 CU23 Feb-2024 SU (15.1.2507.37) ship EP
        # on by default. 2013 was EOL (no fix) -> handled via EOL_PRODUCTS.
        fixed={"Exchange Server 2019": 1544, "Exchange Server 2016": (2507, 37)},
        surface=["/EWS/Exchange.asmx", "/Microsoft-Server-ActiveSync"],
        opsec="medium",
        notes="Mitigated by Extended Protection (EP), default-on from 2019 CU14 "
              "/ 2016 CU23 Feb-2024 SU. Pre-EP builds relay-exposed.",
    ),
    CVE(
        cve="CVE-2024-21413",
        name="MonikerLink",
        impact="NTLM leak / auth bypass via crafted mail link",
        auth="None",
        fixed={},
        surface=[],
        opsec="low",
        notes="Client-side (MonikerLink). Advisory when Exchange present.",
    ),
]


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return the 30x response as-is instead of following it — some detection
    checks (ProxyShell) key off the raw 302 vs 400 status."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpClient:
    def __init__(self, timeout: float = 8.0, verify: bool = False,
                 proxy: Optional[str] = None, ua: Optional[str] = None,
                 verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.request_count = 0
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        base = [urllib.request.HTTPSHandler(context=ctx)]
        if proxy:
            base.append(urllib.request.ProxyHandler(
                {"http": proxy, "https": proxy}))
        self.opener = urllib.request.build_opener(*base)
        self.opener_noredir = urllib.request.build_opener(*base, _NoRedirect())
        self.ua = ua or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
        )

    def request(self, url: str, method: str = "GET",
                headers: Optional[dict] = None,
                allow_redirects: bool = True) -> dict:
        hdrs = {"User-Agent": self.ua}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, method=method, headers=hdrs)
        opener = self.opener if allow_redirects else self.opener_noredir
        self.request_count += 1
        t0 = time.perf_counter()
        try:
            resp = opener.open(req, timeout=self.timeout)
            body = resp.read(65536)
            out = {
                "status": resp.status,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body": body,
                "elapsed": time.perf_counter() - t0,
                "error": None,
            }
        except urllib.error.HTTPError as e:
            # 401/403/500 are all interesting for Exchange fingerprinting.
            out = {
                "status": e.code,
                "headers": {k.lower(): v for k, v in (e.headers or {}).items()},
                "body": (e.read(65536) if hasattr(e, "read") else b""),
                "elapsed": time.perf_counter() - t0,
                "error": None,
            }
        except Exception as e:  # noqa: BLE001 - network layer is noisy by nature
            out = {"status": None, "headers": {}, "body": b"",
                   "elapsed": time.perf_counter() - t0, "error": str(e)}
        self._log(method, url, out, "NTLM" in (headers or {}).get(
            "Authorization", ""))
        return out

    def _log(self, method: str, url: str, out: dict, ntlm: bool):
        if not self.verbose:
            return
        ms = out["elapsed"] * 1000
        tag = out["status"] if out["status"] is not None else (
            f"ERR {out['error']}")
        extra = " [ntlm-negotiate]" if ntlm else ""
        sys.stderr.write(
            f"  -> {method:4} {url}  ==> {tag} ({ms:.0f} ms){extra}\n")
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# NTLM Type-2 (CHALLENGE) parser — extracts domain / host / OS version.
# ---------------------------------------------------------------------------
AV_IDS = {
    1: "netbios_computer",
    2: "netbios_domain",
    3: "dns_computer",
    4: "dns_domain",
    5: "dns_forest",
}


def parse_ntlm_challenge(b64: str) -> Optional[dict]:
    try:
        data = base64.b64decode(b64)
    except Exception:
        return None
    if data[:8] != b"NTLMSSP\x00" or len(data) < 48:
        return None
    if struct.unpack("<I", data[8:12])[0] != 2:  # message type 2
        return None

    out: dict = {}
    # TargetInfo fields block (AV pairs)
    ti_len, _, ti_off = struct.unpack("<HHI", data[40:48])
    if ti_off and ti_off + ti_len <= len(data):
        p = ti_off
        end = ti_off + ti_len
        while p + 4 <= end:
            av_id, av_len = struct.unpack("<HH", data[p:p + 4])
            p += 4
            if av_id == 0:  # MsvAvEOL
                break
            val = data[p:p + av_len]
            p += av_len
            key = AV_IDS.get(av_id)
            if key:
                try:
                    out[key] = val.decode("utf-16-le", errors="replace")
                except Exception:
                    pass

    # OS Version field lives at offset 48 when the negotiate flag is set.
    # Layout: major(1) minor(1) build(2 LE) reserved(3) ntlm_revision(1)
    if len(data) >= 56:
        maj, minr = data[48], data[49]
        build = struct.unpack("<H", data[50:52])[0]
        if maj:
            out["os_version"] = f"{maj}.{minr}.{build}"
    return out


# ---------------------------------------------------------------------------
# Version fingerprinting
# ---------------------------------------------------------------------------
OWA_BUILD_RE = re.compile(r"/owa/auth/(\d+\.\d+\.\d+(?:\.\d+)?)/")
VERSION_HEADER_KEYS = ("x-owa-version", "x-feserver", "x-diaginfo",
                       "request-id", "x-calculatedbetarget")


def build_to_tuple(build: str) -> Optional[tuple]:
    parts = build.split(".")
    try:
        nums = [int(x) for x in parts]
    except ValueError:
        return None
    while len(nums) < 4:
        nums.append(0)
    return tuple(nums[:4])


def product_for_build(t: tuple) -> Optional[str]:
    return PRODUCT_BY_MAJORMINOR.get((t[0], t[1]))


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class Finding:
    endpoint: str
    status: Optional[int]
    server: str = ""
    ntlm: Optional[dict] = None
    note: str = ""


class ExchangeRecon:
    def __init__(self, host: str, http: HttpClient, active: bool = False):
        self.host = host.rstrip("/")
        if not self.host.startswith("http"):
            self.host = "https://" + self.host
        self.http = http
        self.active = active
        self.findings: list[Finding] = []
        self.build: Optional[str] = None
        self.build_tuple: Optional[tuple] = None
        self.product: Optional[str] = None
        self.domain_info: dict = {}
        self.is_exchange = False
        # cve -> {"result": str, "detail": str} from active probes
        self.active_results: dict = {}

    # --- discovery + fingerprint ------------------------------------------
    def probe_endpoint(self, path: str, ntlm: bool) -> Finding:
        url = self.host + path
        r = self.http.request(url, method="GET")
        f = Finding(endpoint=path, status=r["status"])
        if r["error"]:
            f.note = f"error: {r['error']}"
            return f
        hdrs = r["headers"]
        f.server = hdrs.get("server", "")

        # Version disclosure via headers / body (OWA build path).
        self._harvest_version(hdrs, r["body"])

        # Anything that responds like Exchange flips the flag.
        if any(k in hdrs for k in VERSION_HEADER_KEYS) or "owa" in path or \
                "ecp" in path or "EWS" in path or "autodiscover" in path.lower():
            if r["status"] in (200, 301, 302, 401, 403, 500):
                self.is_exchange = True

        # NTLM negotiate for domain/OS extraction.
        if ntlm and r["status"] in (401, 403):
            f.ntlm = self._ntlm_negotiate(url)
            if f.ntlm:
                self.is_exchange = True
                self._merge_domain_info(f.ntlm)
        return f

    def _harvest_version(self, hdrs: dict, body: bytes):
        if self.build:
            return
        # 1) explicit X-OWA-Version header
        v = hdrs.get("x-owa-version")
        if v:
            self._set_build(v)
            return
        # 2) OWA static resource path in body: /owa/auth/15.2.1544/...
        try:
            m = OWA_BUILD_RE.search(body.decode("latin-1", errors="ignore"))
        except Exception:
            m = None
        if m:
            self._set_build(m.group(1))

    def _set_build(self, build: str):
        t = build_to_tuple(build)
        if not t:
            return
        self.build = build
        self.build_tuple = t
        self.product = product_for_build(t)

    def _ntlm_negotiate(self, url: str) -> Optional[dict]:
        r = self.http.request(url, method="GET",
                              headers={"Authorization": "NTLM " + NTLM_TYPE1})
        www = r["headers"].get("www-authenticate", "")
        for tok in www.split(","):
            tok = tok.strip()
            if tok.upper().startswith("NTLM ") and len(tok) > 6:
                info = parse_ntlm_challenge(tok[5:].strip())
                if info:
                    return info
        return None

    def _merge_domain_info(self, info: dict):
        for k, v in info.items():
            self.domain_info.setdefault(k, v)

    # --- active, NON-DESTRUCTIVE confirmation probes ----------------------
    # These positively confirm a flaw is present WITHOUT exploiting it: no
    # webshell, no command execution, no file write. They send the same
    # trigger a scanner uses and read a benign side-effect (a header or an
    # HTTP status). Ported from certat/exchange-scans + GossiTheDog NSE logic.
    def run_active_checks(self):
        if not self.active or not self.is_exchange:
            return
        for cve in CVE_DB:
            if not cve.active_check:
                continue
            fn = getattr(self, cve.active_check, None)
            if fn is None:
                continue
            try:
                result, detail = fn()
            except Exception as e:  # noqa: BLE001
                result, detail = "ERROR", f"probe failed: {e}"
            self.active_results[cve.cve] = {"result": result, "detail": detail}

    def active_proxylogon_ssrf(self):
        """CVE-2021-26855: send the ProxyLogon SSRF cookie and check whether
        the backend proxied our forged 'localhost' target. Confirms the SSRF
        primitive only — it never writes the mailbox/webshell that turns it
        into RCE. Returns (VULNERABLE|NOT_VULNERABLE|INCONCLUSIVE, detail)."""
        url = self.host + "/owa/auth/x.js"
        cookie = ("X-AnonResource=true; "
                  "X-AnonResource-Backend=localhost/ecp/default.flt?~3; "
                  "X-BEResource=localhost/owa/auth/logon.aspx?~3;")
        r = self.http.request(url, method="GET",
                              headers={"Cookie": cookie},
                              allow_redirects=False)
        if r["error"]:
            return "INCONCLUSIVE", f"request error: {r['error']}"
        target = r["headers"].get("x-calculatedbetarget", "")
        if "localhost" in target.lower():
            return "VULNERABLE", (
                f"SSRF confirmed: server proxied forged backend "
                f"(x-calculatedbetarget={target}). RCE-capable, not exploited.")
        if not target:
            return "INCONCLUSIVE", ("No x-calculatedbetarget header — likely "
                                    "patched or fronted by a proxy/WAF.")
        return "NOT_VULNERABLE", (
            f"Backend not overridden (x-calculatedbetarget={target}).")

    def active_proxyshell_pathconfusion(self):
        """CVE-2021-34473: probe the Autodiscover path-confusion that grants
        the pre-auth ACL bypass. A vulnerable server 302-redirects the crafted
        path; a patched one answers 400. Detection only — no PowerShell/RCE
        stage is sent. Returns (VULNERABLE|NOT_VULNERABLE|INCONCLUSIVE, detail)."""
        path = ("/autodiscover/autodiscover.json?@test.com/owa/?&Email="
                "autodiscover/autodiscover.json%3F@test.com")
        r = self.http.request(self.host + path, method="GET",
                              allow_redirects=False)
        if r["error"]:
            return "INCONCLUSIVE", f"request error: {r['error']}"
        st = r["status"]
        if st == 302:
            return "VULNERABLE", (
                "Path-confusion bypass reachable (302 on crafted Autodiscover "
                "path). Pre-auth surface open; RCE stage not sent.")
        if st == 400:
            return "NOT_VULNERABLE", "Server rejected crafted path (400)."
        return "INCONCLUSIVE", f"Unexpected status {st} — verify manually."

    def run_discovery(self, workers: int = 8):
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self.probe_endpoint, p, n): p
                    for p, n in EXCHANGE_ENDPOINTS}
            for fut in concurrent.futures.as_completed(futs):
                self.findings.append(fut.result())
        self.findings.sort(key=lambda f: f.endpoint)

    # --- CVE reasoning -----------------------------------------------------
    def live_endpoints(self) -> set:
        return {f.endpoint for f in self.findings
                if f.status in (200, 301, 302, 401, 403, 500)}

    def assess_cves(self) -> list[dict]:
        results = []
        live = self.live_endpoints()
        # normalize the ProxyShell json probe (not in default list) — treat
        # autodiscover presence as autodiscover.json surface.
        autodiscover_live = any("autodiscover" in e for e in live)

        for cve in CVE_DB:
            verdict, reason = self._verdict_for(cve, live, autodiscover_live)
            results.append({
                "cve": cve.cve,
                "name": cve.name,
                "impact": cve.impact,
                "auth": cve.auth,
                "opsec": cve.opsec,
                "verdict": verdict,
                "reason": reason,
                "notes": cve.notes,
                "active": self.active_results.get(cve.cve),
            })
        # order: confirmed > likely > candidate > advisory > patched/na
        order = {"VULNERABLE": 0, "LIKELY": 1, "CANDIDATE": 2, "ADVISORY": 3,
                 "PATCHED": 4, "N/A": 5}
        results.sort(key=lambda r: order.get(r["verdict"], 9))
        return results

    def _verdict_for(self, cve: CVE, live: set, autodiscover_live: bool):
        # Active probe result wins — it observed real behavior, not a guess.
        ar = self.active_results.get(cve.cve)
        if ar:
            if ar["result"] == "VULNERABLE":
                return "VULNERABLE", "[active] " + ar["detail"]
            if ar["result"] == "NOT_VULNERABLE":
                return "PATCHED", "[active] " + ar["detail"]
            # INCONCLUSIVE / ERROR -> fall through to version-based reasoning.
        # client-side / advisory-only CVEs
        if not cve.surface and not cve.fixed:
            if self.is_exchange:
                return "ADVISORY", ("Client-side issue; flagged because an "
                                    "Exchange surface is present.")
            return "N/A", "No Exchange surface detected."

        # surface check
        surface_present = False
        for s in cve.surface:
            if s in live:
                surface_present = True
                break
            if "autodiscover" in s and autodiscover_live:
                surface_present = True
                break
        if not surface_present:
            return "N/A", "Required attack surface not reachable."

        # version gate
        if cve.fixed and self.build_tuple and self.product:
            fixed = cve.fixed.get(self.product)
            # Compare on (CU, SU) i.e. the 3rd+4th build octets. Some product
            # lines (notably 2013 = 15.0.1497.X) only move the SU, so a CU-only
            # gate would be meaningless — hence the tuple.
            cur = (self.build_tuple[2], self.build_tuple[3])
            if fixed is None:
                # Product not listed by this CVE. For EOL products that usually
                # means "never patched", not "safe".
                if self.product in EOL_PRODUCTS:
                    return "LIKELY", (
                        f"{self.product} is end-of-life and received no fix "
                        f"for this CVE; surface reachable — treat as exposed.")
                return "CANDIDATE", (
                    f"Surface present; {self.product} not in this CVE's "
                    f"affected product list — verify manually.")
            patched = fixed if isinstance(fixed, tuple) else (fixed, 0)
            cur_s = f"{cur[0]}.{cur[1]}"
            pat_s = f"{patched[0]}.{patched[1]}"
            if cur >= patched:
                return "PATCHED", (
                    f"{self.product} build {cur_s} >= patched {pat_s}.")
            return "LIKELY", (
                f"{self.product} build {cur_s} < patched {pat_s} "
                f"and surface reachable.")

        # surface present but no version resolved
        return "CANDIDATE", ("Attack surface reachable but exact build not "
                             "disclosed — confirm version manually.")

    # --- non-CVE weaknesses / exposures -----------------------------------
    # Passive findings derived from what discovery already gathered — no extra
    # traffic. These are the "недостатки" side of the methodology: info leaks,
    # enum/spray surface, exposed admin/remoting endpoints, EOL software.
    def _status_map(self) -> dict:
        return {f.endpoint: f.status for f in self.findings}

    def assess_weaknesses(self) -> list[dict]:
        W: list[dict] = []
        live = self.live_endpoints()
        smap = self._status_map()

        def add(wid, title, sev, evidence, ref):
            W.append({"id": wid, "title": title, "severity": sev,
                      "evidence": evidence, "ref": ref})

        # End-of-life product in production.
        if self.product in EOL_PRODUCTS:
            add("eol-product",
                f"End-of-life Exchange in production ({self.product})", "high",
                f"{self.product} build {self.build or '?'} — no vendor security "
                f"updates ship; permanently exposed to future CVEs.",
                "methodology: patch state / §11")

        # Internal AD/host disclosure via unauthenticated NTLM negotiate.
        if self.domain_info:
            bits = ", ".join(f"{k}={v}" for k, v in self.domain_info.items())
            add("ntlm-internal-disclosure",
                "Internal AD/host info disclosed via unauth NTLM", "medium",
                bits, "methodology §1 (NTLMSSP fingerprint)")

        # Exact build disclosed pre-auth (aids precise CVE targeting).
        if self.build:
            add("version-disclosure",
                "Exact Exchange build disclosed pre-auth", "low",
                f"build {self.build} via X-OWA-Version / OWA resource path",
                "methodology §1")

        # Username enumeration surface (no creds required).
        ntlm_live = sorted(e for e in live if e in NTLM_ENDPOINTS)
        if ntlm_live:
            ev = "time-based NTLM enum via: " + ", ".join(ntlm_live)
            if any("autodiscover" in e for e in live):
                ev += ("; AutodiscoverV2 cookie method via "
                       "/autodiscover/autodiscover.json")
            add("user-enum-surface",
                "Username enumeration surface exposed (no creds)", "medium",
                ev, "methodology §2")

        # Password-spray surface.
        spray = [e for e in ("/owa/", "/EWS/Exchange.asmx",
                             "/Microsoft-Server-ActiveSync",
                             "/autodiscover/autodiscover.xml") if e in live]
        if spray:
            add("password-spray-surface",
                "Auth endpoints exposed for password spraying", "medium",
                "sprayable: " + ", ".join(spray), "methodology §3")

        # ECP admin panel reachable.
        if "/ecp/" in live:
            add("ecp-exposed", "ECP admin panel reachable", "medium",
                f"/ecp/ -> HTTP {smap.get('/ecp/')}",
                "methodology §7 (ECP privilege abuse)")

        # Remote PowerShell endpoint reachable.
        if "/PowerShell/" in live:
            add("powershell-exposed",
                "Remote PowerShell endpoint reachable", "medium",
                f"/PowerShell/ -> HTTP {smap.get('/PowerShell/')}",
                "methodology §6 (ProxyShell PS backend)")

        # ActiveSync exposed — classic MFA-bypass / spray vector.
        if "/Microsoft-Server-ActiveSync" in live:
            add("activesync-exposed",
                "ActiveSync exposed (potential MFA-bypass / spray vector)",
                "low",
                f"/Microsoft-Server-ActiveSync -> "
                f"HTTP {smap.get('/Microsoft-Server-ActiveSync')}",
                "methodology §3")

        # EWS present — SSRF-as-a-feature surface.
        if "/EWS/Exchange.asmx" in live or "/EWS/" in live:
            add("ews-ssrf-surface",
                "EWS present (SSRF-as-feature: Subscribe / "
                "CreateAttachmentFromUri)", "low",
                "EWS endpoint reachable", "methodology §4")

        sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        W.sort(key=lambda w: sev_order.get(w["severity"], 9))
        return W

    # --- report ------------------------------------------------------------
    def to_report(self) -> dict:
        return {
            "scanner": "exchange_recon",
            "version": __version__,
            "target": self.host,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_exchange": self.is_exchange,
            "active_mode": self.active,
            "product": self.product,
            "build": self.build,
            "domain_info": self.domain_info,
            "endpoints": [
                {
                    "endpoint": f.endpoint,
                    "status": f.status,
                    "server": f.server,
                    "ntlm": f.ntlm,
                    "note": f.note,
                }
                for f in self.findings
            ],
            "weaknesses": self.assess_weaknesses(),
            "cve_assessment": self.assess_cves(),
        }


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------
class Color:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    C = "\033[36m"; DIM = "\033[2m"; BOLD = "\033[1m"; X = "\033[0m"

    @classmethod
    def off(cls):
        for a in ("R", "G", "Y", "B", "C", "DIM", "BOLD", "X"):
            setattr(cls, a, "")


VERDICT_COLOR = {
    "VULNERABLE": Color.BOLD + Color.R, "LIKELY": Color.R,
    "CANDIDATE": Color.Y, "ADVISORY": Color.B,
    "PATCHED": Color.G, "N/A": Color.DIM,
}


def print_report(rep: dict):
    C = Color
    print(f"\n{C.BOLD}=== Exchange Recon :: {rep['target']} ==={C.X}")
    print(f"{C.DIM}{rep['timestamp']}{C.X}")
    if not rep["is_exchange"]:
        print(f"{C.Y}[!] No clear Exchange fingerprint on this host.{C.X}")
    else:
        prod = rep["product"] or "Exchange (version undisclosed)"
        build = rep["build"] or "?"
        print(f"{C.C}[+] Product : {prod}{C.X}")
        print(f"{C.C}[+] Build   : {build}{C.X}")
    if rep["domain_info"]:
        print(f"\n{C.BOLD}Domain / host (from NTLM challenge):{C.X}")
        for k, v in rep["domain_info"].items():
            print(f"    {k:18} {v}")

    print(f"\n{C.BOLD}Endpoints:{C.X}")
    for e in rep["endpoints"]:
        st = e["status"]
        col = C.G if st in (200, 301, 302) else (
            C.Y if st in (401, 403) else (C.DIM if st is None else C.R))
        tag = f"{st}" if st is not None else "---"
        extra = ""
        if e["ntlm"] and e["ntlm"].get("os_version"):
            extra = f"  {C.DIM}os={e['ntlm']['os_version']}{C.X}"
        print(f"  {col}{tag:>4}{C.X}  {e['endpoint']}{extra}")

    weaknesses = rep.get("weaknesses", [])
    if weaknesses:
        sev_col = {"high": C.R, "medium": C.Y, "low": C.B, "info": C.DIM}
        print(f"\n{C.BOLD}Weaknesses / exposures (non-CVE):{C.X}")
        print(f"  {C.DIM}severity  finding{C.X}")
        for w in weaknesses:
            col = sev_col.get(w["severity"], "")
            print(f"  {col}{w['severity']:<8}{C.X}  {w['title']}")
            print(f"            {C.DIM}{w['evidence']}{C.X}")
            print(f"            {C.DIM}ref: {w['ref']}{C.X}")

    mode = "active probes ON" if rep.get("active_mode") else "passive (version-based)"
    print(f"\n{C.BOLD}CVE assessment{C.X} {C.DIM}[{mode}]{C.X}")
    print(f"  {C.DIM}verdict     cve              opsec   name{C.X}")
    for c in rep["cve_assessment"]:
        col = VERDICT_COLOR.get(c["verdict"], "")
        print(f"  {col}{c['verdict']:<11}{C.X} {c['cve']:<16} "
              f"{c['opsec']:<7} {c['name']}")
        print(f"      {C.DIM}{c['reason']}{C.X}")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def read_targets(args) -> list[str]:
    targets = list(args.target)
    if args.target_file:
        with open(args.target_file) as fh:
            targets += [ln.strip() for ln in fh if ln.strip()
                        and not ln.startswith("#")]
    return targets


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="exchange_recon",
        description="Non-destructive on-prem Exchange recon & CVE triage "
                    "(detection only — no exploitation).",
        epilog="Authorized testing only. You are responsible for scope.",
    )
    p.add_argument("target", nargs="*",
                   help="host(s): host, host:port, or https://host")
    p.add_argument("-f", "--target-file", help="file with one target per line")
    p.add_argument("-t", "--timeout", type=float, default=8.0,
                   help="per-request timeout seconds (default 8)")
    p.add_argument("-w", "--workers", type=int, default=8,
                   help="concurrent endpoint probes per host (default 8)")
    p.add_argument("-j", "--json", metavar="FILE",
                   help="write JSON report to FILE ('-' for stdout)")
    p.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--ua", help="override User-Agent")
    p.add_argument("--active", action="store_true",
                   help="run active NON-DESTRUCTIVE confirmation probes "
                        "(ProxyLogon SSRF, ProxyShell path-confusion). "
                        "Confirms flaws without exploitation/RCE.")
    p.add_argument("--verify-tls", action="store_true",
                   help="verify TLS certs (default: off, self-signed common)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="log every HTTP request (method, URL, status, timing) "
                        "to stderr — proves requests are actually sent")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress the human-readable report (JSON only)")
    args = p.parse_args(argv)

    targets = read_targets(args)
    if not targets:
        p.error("no targets given (positional or --target-file)")
    if args.no_color or not sys.stdout.isatty():
        Color.off()

    http = HttpClient(timeout=args.timeout, verify=args.verify_tls,
                      proxy=args.proxy, ua=args.ua, verbose=args.verbose)
    reports = []
    for tgt in targets:
        if args.verbose:
            sys.stderr.write(f"[*] scanning {tgt} ...\n")
        rec = ExchangeRecon(tgt, http, active=args.active)
        try:
            rec.run_discovery(workers=args.workers)
            rec.run_active_checks()
        except KeyboardInterrupt:
            print("interrupted", file=sys.stderr)
            return 130
        rep = rec.to_report()
        reports.append(rep)
        if not args.quiet:
            print_report(rep)

    if args.verbose:
        sys.stderr.write(f"[*] total HTTP requests sent: "
                         f"{http.request_count}\n")

    if args.json:
        payload = reports if len(reports) > 1 else reports[0]
        text = json.dumps(payload, indent=2, default=str)
        if args.json == "-":
            print(text)
        else:
            with open(args.json, "w") as fh:
                fh.write(text)
            if not args.quiet:
                print(f"[+] JSON report written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
