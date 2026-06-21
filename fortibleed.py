#!/usr/bin/env python3
"""fortibleed.py — Fortinet leak checker.

-d <domain>    : Hudson Rock Fortinet-domains dataset (rich domain context)
-i <ip>        : SocRadar fortibleed API (single IP)
-r <cidr>      : SocRadar fortibleed API (each host in the CIDR)
-f <file>      : Read mixed targets (domain / ip / cidr) from file, one per line
"""

import argparse
import ipaddress
import json
import sys
import time
from urllib.parse import quote

import requests

VERBOSE = False
USE_COLOR = sys.stdout.isatty()
OUT_FH = None  # optional file handle for -o

GREEN = "\033[32m"
BGREEN = "\033[1;32m"
RESET = "\033[0m"


def green(s: str) -> str:
    return f"{GREEN}{s}{RESET}" if USE_COLOR else s


def bgreen(s: str) -> str:
    return f"{BGREEN}{s}{RESET}" if USE_COLOR else s


def vlog(msg: str) -> None:
    if VERBOSE:
        print(f"[v] {msg}", file=sys.stderr)


import re
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def emit(msg: str) -> None:
    """Print to stdout (with color if enabled) and mirror plain text to -o file."""
    print(msg, flush=True)
    if OUT_FH is not None:
        OUT_FH.write(_ANSI_RE.sub("", msg) + "\n")
        OUT_FH.flush()

HUDSON_API = (
    "https://www.hudsonrock.com/api/json/v2/stats/website-results/"
    "fortinet-domains/search"
)
SOCRADAR_API = "https://socradar.io/free-tools/api/fortibleed/search-fortibleed"
SOCRADAR_BEARER = (
    "5a998c2bdf1f3b36b8cad6bfb139ce432ff1b823dd9df3fe4a68cecc8ccbae9a"
)
SOCRADAR_CSRF = "eaNOeebKCrbC5VS5Lqq02RVtG9L1alo8mJBUkg_tI2Q"

HUDSON_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.hudsonrock.com/fortinet",
    "Content-Type": "application/json",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}

SOCRADAR_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:152.0) "
        "Gecko/20100101 Firefox/152.0"
    ),
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://socradar.io/free-tools/fortibleed",
    "Authorization": f"Bearer {SOCRADAR_BEARER}",
    "Content-Type": "application/json",
    "X-Csrf-Token": SOCRADAR_CSRF,
    "Origin": "https://socradar.io",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}


# ---------- Hudson Rock (domain) ----------

def hudson_fetch(query: str, page: int = 1) -> dict:
    url = f"{HUDSON_API}?q={quote(query)}&page={page}"
    vlog(f"GET {url}")
    t0 = time.perf_counter()
    r = requests.get(url, headers=HUDSON_HEADERS, timeout=30)
    dt = (time.perf_counter() - t0) * 1000
    vlog(f"  -> {r.status_code} {len(r.content)}B in {dt:.0f}ms")
    r.raise_for_status()
    return r.json()


def hudson_fetch_all(query: str, max_pages: int = 50) -> list:
    vlog(f"hudson search q={query!r}")
    out, page = [], 1
    seen_domains = set()
    last_page_key = None
    while True:
        payload = hudson_fetch(query, page)
        page_data = payload.get("data", []) or []
        vlog(f"  page {page}: {len(page_data)} record(s), "
             f"hasMore={payload.get('hasMore')}")

        # Detect API ignoring &page= (returns same payload every time).
        page_key = tuple(rec.get("domain") for rec in page_data)
        if page_key == last_page_key and page_key:
            vlog(f"  identical to previous page — server isn't paginating, stopping")
            break
        last_page_key = page_key

        # Skip duplicate records if the server repeats some across pages.
        fresh = [rec for rec in page_data
                 if rec.get("domain") not in seen_domains]
        if not fresh and page_data:
            vlog(f"  no new domains on this page — stopping")
            break
        for rec in fresh:
            seen_domains.add(rec.get("domain"))
        out.extend(fresh)

        if not payload.get("hasMore"):
            break
        if page >= max_pages:
            vlog(f"  hit max_pages={max_pages}, stopping (server claims hasMore)")
            break
        page += 1
    vlog(f"hudson total: {len(out)} record(s)")
    return out


def domain_matches(query: str, record_domain: str) -> bool:
    """Strict match: record domain must equal the query exactly,
    or be a subdomain of it. Case-insensitive. No parent / token matching."""
    if not record_domain:
        return False
    q = query.lower().lstrip(".")
    d = record_domain.lower()
    return d == q or d.endswith("." + q)


def filter_hudson(records: list, query: str) -> list:
    return [r for r in records if domain_matches(query, r.get("domain", ""))]


def render_hudson(records: list) -> None:
    if not records:
        print("[-] No results.")
        return
    for rec in records:
        emit("=" * 70)
        emit(f"Domain    : {bgreen(rec.get('domain') or '')}")
        emit(f"Industry  : {rec.get('industry')}")
        emit(f"Size      : {rec.get('size')}")
        emit(f"Revenue   : {rec.get('revenue')}")
        counts = rec.get("counts", {}) or {}
        emit(f"Users     : {counts.get('users', 0)}")
        emit(f"Employees : {counts.get('employees', 0)}")
        creds = rec.get("credentials", []) or []
        if creds:
            emit("Credentials:")
            for c in creds:
                emit(f"  - URL          : {green(c.get('url') or '')}")
                emit(f"    FortiGuardID : {green(c.get('FortiGuardID') or '')}")
                emit(f"    Country      : {c.get('country')}")
    emit("=" * 70)
    emit(green(f"[+] {len(records)} record(s)."))


# ---------- SocRadar (ip / range) ----------

def socradar_query(query: str) -> dict:
    vlog(f"POST {SOCRADAR_API} body={{\"query\": {query!r}}}")
    t0 = time.perf_counter()
    r = requests.post(
        SOCRADAR_API,
        headers=SOCRADAR_HEADERS,
        json={"query": query},
        timeout=30,
    )
    dt = (time.perf_counter() - t0) * 1000
    vlog(f"  -> {r.status_code} {len(r.content)}B in {dt:.0f}ms")
    r.raise_for_status()
    return r.json()


def render_socradar(query: str, payload: dict) -> bool:
    """Print one SocRadar result. Returns True if leak detected."""
    data = (payload or {}).get("data") or {}
    detected = bool(data.get("is_detected"))
    match_count = data.get("match_count", 0)
    qtype = data.get("query_type", "?")
    tags = ",".join(data.get("tags") or []) or "-"

    if detected:
        line = (f"[!] {query} ({qtype})  detected={detected}  "
                f"matches={match_count}  tags={tags}")
        emit(bgreen(line))
        cats = [c for c in (data.get("categories") or []) if c.get("detected")]
        if cats:
            cat_str = ", ".join(f"{c['label']}({c['count']})" for c in cats)
            emit(green(f"    categories: {cat_str}"))
        for m in (data.get("matches") or []):
            emit(green(f"    match: {m.get('value')} [{m.get('value_type')}] "
                       f"tags={','.join(m.get('tags') or [])}"))
    else:
        print(f"[ ] {query} ({qtype})  detected={detected}  "
              f"matches={match_count}  tags={tags}")
    return detected


def iter_hosts(cidr: str):
    net = ipaddress.ip_network(cidr, strict=False)
    # For /31 and /32, hosts() returns 0 or 1 — fall back to the network itself.
    hosts = list(net.hosts()) or [net.network_address]
    return [str(h) for h in hosts]


def classify(entry: str) -> str:
    """Return 'ip', 'cidr', or 'domain'."""
    if "/" in entry:
        try:
            ipaddress.ip_network(entry, strict=False)
            return "cidr"
        except ValueError:
            pass
    try:
        ipaddress.ip_address(entry)
        return "ip"
    except ValueError:
        pass
    return "domain"


def read_targets(path: str) -> list:
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line)
    return out


# ---------- CLI ----------

def main() -> int:
    p = argparse.ArgumentParser(
        description="Fortinet leak checker (Hudson Rock + SocRadar fortibleed).",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-d", "--domain", help="Domain or substring (Hudson Rock)")
    g.add_argument("-i", "--ip", help="Single IP (SocRadar)")
    g.add_argument("-r", "--range", dest="cidr",
                   help="CIDR range, e.g. 192.168.1.0/24 (SocRadar, per host)")
    g.add_argument("-f", "--file",
                   help="File with mixed targets (domain/ip/cidr), one per line")
    p.add_argument("--json", action="store_true", help="Print raw JSON")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose request/decision logging to stderr")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colors even on a TTY")
    p.add_argument("-o", "--output",
                   help="Append hit output (no colors) to this file")
    args = p.parse_args()

    global VERBOSE, USE_COLOR, OUT_FH
    VERBOSE = args.verbose
    if args.no_color:
        USE_COLOR = False
    if args.output:
        OUT_FH = open(args.output, "a", encoding="utf-8")

    try:
        if args.domain:
            records = hudson_fetch_all(args.domain)
            filtered = filter_hudson(records, args.domain)
            vlog(f"filter: {len(records)} -> {len(filtered)} "
                 f"matching {args.domain!r}")
            if args.json:
                print(json.dumps(filtered, indent=2))
            else:
                render_hudson(filtered)
            return 0

        if args.ip:
            ipaddress.ip_address(args.ip)  # validate
            payload = socradar_query(args.ip)
            if args.json:
                print(json.dumps(payload, indent=2))
            else:
                render_socradar(args.ip, payload)
            return 0

        if args.cidr:
            hosts = iter_hosts(args.cidr)
            print(f"[+] Scanning {len(hosts)} host(s) in {args.cidr} ...")
            hits = []
            results = {}
            for ip in hosts:
                try:
                    payload = socradar_query(ip)
                except requests.RequestException as e:
                    print(f"[!] {ip} request failed: {e}", file=sys.stderr)
                    continue
                results[ip] = payload
                if args.json:
                    continue
                if render_socradar(ip, payload):
                    hits.append(ip)
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                print(f"[+] Done. {len(hits)}/{len(hosts)} detected.")
                if hits:
                    print(green("    hits: " + ", ".join(hits)))
            return 0

        # file mode
        entries = read_targets(args.file)
        if not entries:
            print(f"[!] No targets in {args.file}", file=sys.stderr)
            return 2

        # Expand CIDRs into individual IPs while preserving order/source.
        plan = []  # list of (target, kind)
        for entry in entries:
            kind = classify(entry)
            vlog(f"classify {entry!r} -> {kind}")
            if kind == "cidr":
                hosts = iter_hosts(entry)
                vlog(f"  expand {entry} -> {len(hosts)} host(s)")
                for ip in hosts:
                    plan.append((ip, "ip"))
            else:
                plan.append((entry, kind))

        print(f"[+] Loaded {len(entries)} line(s) from {args.file} "
              f"-> {len(plan)} target(s).", flush=True)
        results = {}
        hits = []
        total = len(plan)
        progress_tty = sys.stderr.isatty() and not args.json

        def clear_progress():
            if progress_tty:
                sys.stderr.write("\r\033[K")
                sys.stderr.flush()

        def show_progress(i, target):
            if progress_tty:
                sys.stderr.write(f"\r\033[K[{i}/{total}] {target}")
                sys.stderr.flush()

        for idx, (target, kind) in enumerate(plan, 1):
            show_progress(idx, target)
            try:
                if kind == "domain":
                    records = hudson_fetch_all(target)
                    records = filter_hudson(records, target)
                    results[target] = records
                    if args.json:
                        continue
                    if not records:
                        continue
                    clear_progress()
                    emit(bgreen(f"[!] {target} (domain)  records={len(records)}"))
                    render_hudson(records)
                    hits.append(target)
                else:  # ip
                    payload = socradar_query(target)
                    results[target] = payload
                    if args.json:
                        continue
                    if (payload or {}).get("data", {}).get("is_detected"):
                        clear_progress()
                        render_socradar(target, payload)
                        sys.stdout.flush()
                        hits.append(target)
            except requests.RequestException as e:
                clear_progress()
                print(f"[!] {target} request failed: {e}",
                      file=sys.stderr, flush=True)

        clear_progress()
        if args.json:
            payload = json.dumps(results, indent=2)
            print(payload)
            if OUT_FH is not None:
                OUT_FH.write(payload + "\n")
        else:
            print(f"[+] Done. {len(hits)}/{total} detected.")
            if hits:
                emit(green("    hits: " + ", ".join(hits)))
        return 0

    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        return 1
    finally:
        if OUT_FH is not None:
            OUT_FH.close()


if __name__ == "__main__":
    sys.exit(main())
