import socket
import concurrent.futures
import requests
import json
import os
import time
import threading
import ipaddress
import urllib.parse
import ssl
import shelve
import random
import string
from datetime import datetime
from typing import List, Dict, Any

from dotenv import load_dotenv
load_dotenv()

# ---------------- Configuration ----------------
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
ABUSE_MIN_INTERVAL = float(os.getenv("ABUSE_MIN_INTERVAL", "1.0"))
ABUSE_CACHE_DB = os.getenv("ABUSE_CACHE_DB", "abuse_cache.db")
TLS_CACHE_DB = os.getenv("TLS_CACHE_DB", "tls_cache.db")

DEFAULT_TIMEOUT = 0.5
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]

# Active test controls (safe defaults)
ACTIVE_TESTS_MAX_PARAM_TESTS = 3        # max different query params to test per URL
ACTIVE_TESTS_TIMEOUT = 5.0              # per-request timeout
ACTIVE_TESTS_MAX_BATCH = 6              # max URLs per active batch
ACTIVE_TESTS_USER_AGENT = "IDS-Scanner/1.0 (+active-tests)"  # identifies the scanner

# concurrency & throttling
_abuse_lock = threading.Lock()
_last_abuse_call = 0.0

# shelve helpers
def _open_abuse_shelve(writeback=False):
    return shelve.open(ABUSE_CACHE_DB, writeback=writeback)

def _open_tls_shelve(writeback=False):
    return shelve.open(TLS_CACHE_DB, writeback=writeback)

# ---------------- Utilities ----------------
def resolve_host(host: str) -> List[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except Exception:
        pass
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        return sorted({item[4][0] for item in infos})
    except Exception:
        return [host]

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def normalize_targets(text: str) -> List[str]:
    parts = []
    for segment in text.splitlines():
        for sub in segment.split(","):
            s = sub.strip()
            if s:
                parts.append(s)
    seen = set()
    out = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out

# ---------------- Port scanning ----------------
def _scan_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False

def port_scan(ip: str, ports: List[int], timeout: float = DEFAULT_TIMEOUT, max_workers: int = 20) -> List[int]:
    open_ports = []
    workers = min(max_workers, max(4, len(ports)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_scan_port, ip, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            p = futures[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass
    return sorted(open_ports)

# ---------------- AbuseIPDB integration ----------------
def _call_abuseipdb(ip: str) -> Dict[str, Any]:
    if not ABUSEIPDB_KEY:
        return {"error": "No AbuseIPDB key set in environment"}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_KEY}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=7)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "totalReports": data.get("totalReports"),
                "countryCode": data.get("countryCode"),
                "usageType": data.get("usageType"),
                "isp": data.get("isp")
            }
        else:
            return {"error": f"AbuseIPDB API returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_abuse_cached(ip: str, ttl: int = 3600) -> Dict[str, Any]:
    now = time.time()
    with _open_abuse_shelve() as db:
        entry = db.get(ip)
        if entry and (now - entry.get("_ts", 0) < ttl):
            return entry.get("data", {})
    global _last_abuse_call
    with _abuse_lock:
        now = time.time()
        wait = ABUSE_MIN_INTERVAL - (now - _last_abuse_call)
        if wait > 0:
            time.sleep(wait)
        _last_abuse_call = time.time()
    data = _call_abuseipdb(ip)
    with _open_abuse_shelve(writeback=True) as db:
        db[ip] = {"_ts": time.time(), "data": data}
    return data

# ---------------- TLS certificate (cached) ----------------
def fetch_tls_info_live(host: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                issuer = cert.get("issuer")
                subject = cert.get("subject")
                not_after = cert.get("notAfter")
                san = cert.get("subjectAltName", ())
                sans = [v for (k, v) in san] if san else []
                return {"issuer": issuer, "subject": subject, "notAfter": not_after, "SANs": sans}
    except Exception as e:
        return {"error": str(e)}

def get_tls_cached(host: str, port: int = 443, ttl: int = 24*3600) -> Dict[str, Any]:
    key = f"{host}:{port}"
    now = time.time()
    with _open_tls_shelve() as db:
        entry = db.get(key)
        if entry and (now - entry.get("_ts", 0) < ttl):
            return entry.get("data", {})
    data = fetch_tls_info_live(host, port)
    with _open_tls_shelve(writeback=True) as db:
        db[key] = {"_ts": time.time(), "data": data}
    return data

# ---------------- Passive website scan ----------------
def scan_website_url(url: str, check_paths: List[str] = None, timeout: float = 6.0, active_tests: bool = False) -> Dict[str, Any]:
    """
    Safe passive checks for a website URL plus optional low-impact active tests when active_tests=True.
    active_tests must be explicitly enabled by the caller.
    """
    if not url:
        return {"error": "No URL provided"}

    parsed = urllib.parse.urlparse(url if "://" in url else ("http://" + url))
    scheme = parsed.scheme or "http"
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    if not host:
        return {"error": "Invalid URL/host"}

    timestamp = datetime.utcnow().isoformat() + "Z"
    ips = resolve_host(host)

    out: Dict[str, Any] = {
        "timestamp": timestamp,
        "url": url,
        "host": host,
        "scheme": scheme,
        "port": port,
        "resolved_ips": ips,
        "reputation": {},
        "http": {},
        "tls": {},
        "robots": {},
        "interesting_paths": {},
        "active_tests_run": False,
        "suspicionReasons": []
    }

    # reputation for resolved IPs
    for ip in ips:
        if is_private_ip(ip):
            out["reputation"][ip] = {"note": "private"}
        else:
            out["reputation"][ip] = get_abuse_cached(ip)

    # HTTP GET root (passive)
    try:
        ua = {"User-Agent": "IDS-Scanner/1.0 (+defensive-testing)"}
        root_url = url if "://" in url else f"{scheme}://{host}"
        resp = requests.get(root_url, headers=ua, timeout=timeout, allow_redirects=True, verify=True)
        out["http"]["status_code"] = resp.status_code
        out["http"]["final_url"] = resp.url
        out["http"]["headers"] = dict(resp.headers)
        server_banner = resp.headers.get("Server")
        if server_banner:
            out["http"]["server"] = server_banner
        body = resp.text[:3000] if resp.text else ""
        cms = []
        if "wp-content" in body or "wp-includes" in body:
            cms.append("WordPress")
        if "Joomla!" in body:
            cms.append("Joomla")
        if "Drupal.settings" in body:
            cms.append("Drupal")
        out["http"]["cms_candidates"] = cms
    except requests.exceptions.SSLError as e:
        out["http"]["error"] = f"SSL error: {e}"
    except Exception as e:
        out["http"]["error"] = str(e)

    # TLS info (cached) for HTTPS
    if scheme == "https":
        out["tls"] = get_tls_cached(host, port=port)

    # robots.txt
    try:
        robots_url = f"{scheme}://{host}/robots.txt"
        r = requests.get(robots_url, timeout=timeout, headers={"User-Agent": "IDS-Scanner/1.0"}, allow_redirects=True, verify=True)
        out["robots"]["status_code"] = r.status_code
        if r.status_code == 200:
            out["robots"]["content_snippet"] = r.text[:2000]
    except Exception as e:
        out["robots"]["error"] = str(e)

    # interesting paths HEAD check
    if check_paths is None:
        check_paths = ["/admin", "/login", "/wp-login.php", "/.git/", "/.env", "/config.php", "/server-status"]
    for p in check_paths:
        try:
            path_url = f"{scheme}://{host}{p}"
            head = requests.head(path_url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "IDS-Scanner/1.0"}, verify=True)
            out["interesting_paths"][p] = {"status_code": head.status_code, "final_url": head.url}
        except Exception as e:
            out["interesting_paths"][p] = {"error": str(e)}

    # ---------------- Optional low-impact active tests ----------------
    active_results = {}
    if active_tests:
        # REQUIRE explicit caller opt-in: active_tests=True is required
        out["active_tests_run"] = True
        try:
            active_results = _run_active_checks_safe(root_url= root_url, host=host, scheme=scheme, timeout=ACTIVE_TESTS_TIMEOUT)
            out["active_tests"] = active_results
        except Exception as e:
            out["active_tests_error"] = str(e)

    # ---------------- Build concise scanSummary and suspicious flags ----------------
    reasons = []
    is_suspicious = False

    # Reputation-based rule
    for ip, rep in out["reputation"].items():
        if isinstance(rep, dict) and rep.get("abuseConfidenceScore") is not None:
            try:
                if int(rep["abuseConfidenceScore"]) >= 50:
                    is_suspicious = True
                    reasons.append(f"High abuse score on {ip} ({rep['abuseConfidenceScore']})")
            except Exception:
                pass
        elif isinstance(rep, dict) and rep.get("error"):
            reasons.append(f"Reputation lookup error for {ip}: {rep.get('error')}")

    # Interesting paths
    for p, info in out["interesting_paths"].items():
        if isinstance(info, dict) and info.get("status_code") and info["status_code"] < 400:
            is_suspicious = True
            reasons.append(f"{p} accessible (HTTP {info['status_code']})")

    # Weak/missing security headers (passive)
    headers = out.get("http", {}).get("headers", {}) or {}
    if headers:
        if "X-Frame-Options" not in headers:
            reasons.append("Missing X-Frame-Options")
        if ("Content-Security-Policy" not in headers) and ("Content-Security-Policy-Report-Only" not in headers):
            reasons.append("Missing CSP header")

    # Active tests results (if run) -> add reasons if they flagged
    if active_results:
        # reflected_xss
        rx = active_results.get("reflected_xss", {})
        if rx.get("reflected"):
            is_suspicious = True
            reasons.append(f"Reflected input found in response (possible reflected XSS) - param(s): {', '.join(rx.get('params',[]))}")
        # sql_errors
        se = active_results.get("sql_errors", {})
        if se.get("found"):
            is_suspicious = True
            reasons.append(f"SQL error-like content found in response (params: {', '.join(se.get('params',[]))})")
        # dir_listing
        dl = active_results.get("directory_listing", {})
        if dl.get("found"):
            is_suspicious = True
            reasons.append("Directory listing detected on root or specific path")

    out["isSuspicious"] = is_suspicious
    out["suspicionReasons"] = reasons
    out["scanSummary"] = "Suspicious" if is_suspicious else "Clean"
    return out

# ---------------- Active checks (low-impact, opt-in) ----------------
def _random_token(n=12):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def _run_active_checks_safe(root_url: str, host: str, scheme: str, timeout: float = ACTIVE_TESTS_TIMEOUT) -> Dict[str, Any]:
    """
    Run a limited set of low-impact active checks:
      - reflected XSS detection: inject unique token in a few query params and see if reflected
      - SQL error injection: send a "'" in param and search for common SQL error strings
      - directory listing detection: check root body for 'Index of /' or 'Directory listing for'
    IMPORTANT: caller must explicitly opt-in by passing active_tests=True.
    """
    results = {"reflected_xss": {"reflected": False, "params": []},
               "sql_errors": {"found": False, "params": []},
               "directory_listing": {"found": False}}

    # fetch root body (we already did a passive GET in caller, but do a small GET here)
    try:
        resp = requests.get(root_url, timeout=timeout, headers={"User-Agent": ACTIVE_TESTS_USER_AGENT}, allow_redirects=True, verify=True)
        body = resp.text or ""
    except Exception:
        body = ""

    # Directory listing heuristic
    if body:
        if ("Index of /" in body) or ("Directory listing for" in body) or ("<title>Index of" in body):
            results["directory_listing"]["found"] = True

    # For param-based checks we must avoid modifying forms or destructive endpoints.
    # Strategy:
    # - Build up to ACTIVE_TESTS_MAX_PARAM_TESTS different query params with a unique token
    # - Only test by GET to root_url + ?p1=TOKEN, ?q=TOKEN2, etc.
    # - Look for token reflection (reflected_xss) and for SQL error indicators.
    try:
        # Parse existing query to preserve path
        parsed = urllib.parse.urlparse(root_url)
        base_path = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
        # prepare some safe param names
        param_names = ["q", "search", "id", "p"]
        tested_params = param_names[:ACTIVE_TESTS_MAX_PARAM_TESTS]
        for pname in tested_params:
            token = "__IDS_TOKEN_" + _random_token(8) + "__"
            test_url = base_path
            # add a simple param
            sep = '&' if parsed.query else '?'
            test_url = base_path + ("?" + pname + "=" + urllib.parse.quote(token))
            # perform safe GET
            try:
                r = requests.get(test_url, timeout=timeout, headers={"User-Agent": ACTIVE_TESTS_USER_AGENT}, allow_redirects=True, verify=True)
                text = r.text or ""
                # reflected XSS heuristic: token appears verbatim in response body
                if token in text:
                    results["reflected_xss"]["reflected"] = True
                    results["reflected_xss"]["params"].append(pname)
                # SQL error heuristic: look for common db error fragments
                sql_error_signatures = [
                    "sql syntax", "mysql", "syntax to use", "unterminated quoted string", "syntax error", "ODBC", "ORA-",
                    "SQLSTATE", "PostgreSQL", "SQLite/3", "Microsoft OLE DB Provider", "Invalid Querystring"
                ]
                lower = text.lower()
                for sig in sql_error_signatures:
                    if sig.lower() in lower:
                        results["sql_errors"]["found"] = True
                        results["sql_errors"]["params"].append(pname)
                        break
            except Exception:
                # ignore individual request errors
                pass
    except Exception:
        pass

    return results

# ---------------- Main target scanning (IP/domain) ----------------
def scan_target(target: str, ports: List[int] = None, blacklist_file: str = "malicious_ips.txt") -> Dict[str, Any]:
    """
    Scan IP or domain (resolves domain). Includes port scan + reputation.
    This function is separate from website scanning; use scan_website_url for URL-level checks.
    """
    ports = ports or COMMON_PORTS
    timestamp = datetime.utcnow().isoformat() + "Z"
    ips = resolve_host(target)
    blacklist = set()
    if os.path.exists(blacklist_file):
        with open(blacklist_file, "r") as f:
            blacklist = {ln.strip() for ln in f if ln.strip() and not ln.startswith("#")}

    results = {
        "timestamp": timestamp,
        "target": target,
        "resolved_ips": ips,
        "suspicious": False,
        "reasons": [],
        "open_ports": {},
        "reputation": {}
    }

    for ip in ips:
        if is_private_ip(ip):
            results["reasons"].append(f"{ip} is private IP; skipping")
            results["open_ports"][ip] = []
            results["reputation"][ip] = {"note": "private"}
            continue

        if ip in blacklist:
            results["suspicious"] = True
            results["reasons"].append(f"{ip} found in local blacklist")

        openp = port_scan(ip, ports, timeout=DEFAULT_TIMEOUT, max_workers=20)
        results["open_ports"][ip] = openp
        if openp:
            results["reasons"].append(f"Open ports {openp} on {ip}")

        rep = get_abuse_cached(ip)
        results["reputation"][ip] = rep
        if isinstance(rep, dict) and rep.get("abuseConfidenceScore") is not None:
            try:
                if int(rep["abuseConfidenceScore"]) >= 50:
                    results["suspicious"] = True
                    results["reasons"].append(f"{ip} flagged by AbuseIPDB (score {rep['abuseConfidenceScore']})")
            except Exception:
                pass
        elif isinstance(rep, dict) and rep.get("error"):
            results["reasons"].append(f"Reputation check error for {ip}: {rep.get('error')}")
    return results

# ---------------- Quick / batch helpers ----------------
def scan_single_target_quick(target: str) -> Dict[str, Any]:
    timestamp = datetime.utcnow().isoformat() + "Z"
    ips = resolve_host(target)
    out = {"timestamp": timestamp, "target": target, "resolved_ips": ips, "reputation": {}, "open_ports": []}
    for ip in ips:
        if is_private_ip(ip):
            out["reputation"][ip] = {"note": "private"}
            out["open_ports"] = []
            continue
        out["reputation"][ip] = get_abuse_cached(ip)
    return out

def scan_single_target_full(target: str, ports: List[int]) -> Dict[str, Any]:
    return scan_target(target, ports=ports)

def scan_website_batch(urls: List[str], active_tests: bool = False, max_concurrent: int = 4, timeout: float = 6.0) -> Dict[str, Any]:
    """Scan multiple website URLs (passive + optional active). Limited batch size for safety."""
    if active_tests and len(urls) > ACTIVE_TESTS_MAX_BATCH:
        return {"error": f"Too many URLs in active batch (max {ACTIVE_TESTS_MAX_BATCH})"}
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_concurrent, max(2, len(urls)))) as ex:
        futures = {ex.submit(scan_website_url, u, timeout=timeout, active_tests=active_tests): u for u in urls}
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"url": futures[fut], "error": str(e)})
    return {"scanned": len(results), "results": results}

# ---------------- helpers for CLI or saving ----------------
def save_json(results: dict, path: str):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)

# ---------------- parse ports arg ----------------
def parse_ports_arg(ports_arg: str):
    if not ports_arg:
        return COMMON_PORTS
    if isinstance(ports_arg, (list, tuple)):
        return ports_arg
    if str(ports_arg).lower() == "common":
        return COMMON_PORTS
    ports = set()
    for part in str(ports_arg).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                ports.update(range(int(a), int(b) + 1))
            except Exception:
                pass
        else:
            try:
                ports.add(int(part))
            except Exception:
                pass
    return sorted(p for p in ports if 0 < p < 65536)

# ---------------- CLI entrypoint ----------------
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--website", help="URL to scan (passive).", default=None)
    ap.add_argument("--active", action="store_true", help="Enable low-impact active checks (must have permission).")
    ap.add_argument("--batch", help="Newline/comma separated list for batch website scan", default=None)
    args = ap.parse_args()

    if args.batch:
        urls = normalize_targets(args.batch)
        out = scan_website_batch(urls, active_tests=args.active)
        print(json.dumps(out, indent=2))
    elif args.website:
        out = scan_website_url(args.website, active_tests=args.active)
        print(json.dumps(out, indent=2))
    else:
        print("Usage example: python suspicious_scanner.py --website example.com [--active]")

