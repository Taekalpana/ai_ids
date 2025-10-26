# ids/website_scanner.py
import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup  # pip install beautifulsoup4
import ssl
import socket
from typing import List, Dict, Any, Set
from suspicious_scanner import resolve_host, port_scan, check_abuseipdb, is_private_ip, COMMON_PORTS

# ----------------- Helpers -----------------
REQUEST_TIMEOUT = 6  # seconds for HTTP requests

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-xss-protection",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "expect-ct",
]

def normalize_url(url: str) -> str:
    """Ensure URL has scheme."""
    if not re.match(r"^https?://", url):
        url = "https://" + url
    return url

def extract_same_origin_links(base_url: str, html: str, max_links: int = 30) -> Set[str]:
    """
    Parse HTML and return set of same-origin hostnames (including subdomains).
    Limit number to avoid big crawls.
    """
    hosts = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
        count = 0
        base_parsed = urlparse(base_url)
        for a in soup.find_all("a", href=True):
            if count >= max_links:
                break
            href = a["href"].strip()
            # create absolute URL
            try:
                abs_url = urljoin(base_url, href)
                parsed = urlparse(abs_url)
                if parsed.hostname and parsed.scheme in ("http", "https"):
                    # only same origin scheme/host or subdomain of base
                    # accept if hostname endswith base domain
                    base_domain = base_parsed.hostname
                    if parsed.hostname == base_domain or parsed.hostname.endswith("." + base_domain):
                        hosts.add(parsed.hostname)
                        count += 1
            except Exception:
                continue
    except Exception:
        pass
    return hosts

def check_http_security(url: str) -> Dict[str, Any]:
    """Fetch URL and inspect headers and https availability."""
    result = {
        "url": url,
        "status_code": None,
        "https_ok": False,
        "security_headers": {},
        "server_header": None,
        "error": None
    }
    try:
        # prefer https first
        r = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=True)
        result["status_code"] = r.status_code
        result["server_header"] = r.headers.get("Server")
        # security headers presence/values
        for h in SECURITY_HEADERS:
            val = r.headers.get(h) or r.headers.get(h.title())
            if val:
                result["security_headers"][h] = val
            else:
                result["security_headers"][h] = None
        result["https_ok"] = (r.url.startswith("https://"))
    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return result

def quick_tls_check(host: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    """Attempt to retrieve certificate details (non-invasive)."""
    out = {"host": host, "port": port, "cert_ok": False, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # cert is present, consider it OK if no exception
                out["cert_ok"] = True
                out["cert_subject"] = cert.get("subject")
                out["cert_issuer"] = cert.get("issuer")
                out["cert_notAfter"] = cert.get("notAfter")
    except Exception as e:
        out["error"] = str(e)
    return out

# ----------------- Main website scanner -----------------
def scan_website(url: str, ports: List[int] = None, crawl: bool = True, max_hosts: int = 8) -> Dict[str, Any]:
    """
    Scans a website URL:
      - normalize URL
      - fetch homepage and inspect headers
      - optionally extract same-origin hostnames (subdomains) from links (shallow)
      - for all hostnames resolve to IPs and run port/reputation checks
      - check TLS certificate (if https)
    """
    ports = ports or COMMON_PORTS
    url = normalize_url(url)
    parsed = urlparse(url)
    base_host = parsed.hostname

    report = {
        "target_url": url,
        "timestamp": None,
        "http_check": None,
        "hosts_scanned": {},
        "summary": {
            "suspicious_hosts": [],
            "total_hosts": 0
        }
    }

    # 1) HTTP check for base URL
    report["http_check"] = check_http_security(url)

    # 2) optionally crawl homepage for same-origin hostnames (shallow)
    hostnames = {base_host}
    if crawl:
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=True)
            html = r.text
            found = extract_same_origin_links(url, html, max_links=30)
            for h in found:
                hostnames.add(h)
        except Exception:
            pass

    # limit hosts to max_hosts to avoid long scans
    hostnames = list(hostnames)[:max_hosts]
    report["summary"]["total_hosts"] = len(hostnames)

    # 3) For each host: resolve, scan ports, reputation, TLS
    for host in hostnames:
        host_entry = {
            "resolved_ips": [],
            "open_ports": {},
            "reputation": {},
            "is_private": False,
            "tls": None
        }
        try:
            ips = resolve_host(host)
        except Exception:
            ips = [host]  # fallback

        host_entry["resolved_ips"] = ips
        host_entry["is_private"] = all(is_private_ip(ip) for ip in ips if ip)

        # TLS check for host if URL scheme https or port 443 reachable
        if parsed.scheme == "https":
            host_entry["tls"] = quick_tls_check(host, port=443)

        # scan each IP
        host_suspicious = False
        for ip in ips:
            if is_private_ip(ip):
                host_entry["open_ports"][ip] = []
                host_entry["reputation"][ip] = {"note": "private IP"}
                continue

            open_ports = port_scan(ip, ports)
            host_entry["open_ports"][ip] = open_ports

            rep = check_abuseipdb(ip)
            host_entry["reputation"][ip] = rep

            # mark suspicious heuristics
            score = 0
            if isinstance(rep, dict):
                acs = rep.get("abuseConfidenceScore")
                if acs is not None:
                    try:
                        if int(acs) >= 50:
                            host_suspicious = True
                    except Exception:
                        pass
                total_reports = rep.get("totalReports", 0)
                if isinstance(total_reports, int) and total_reports > 10:
                    host_suspicious = True

            # if known dangerous port open, mark suspicious (RDP/SMB etc)
            dangerous = {3389, 445}
            if any(p in dangerous for p in open_ports):
                host_suspicious = True

        report["hosts_scanned"][host] = host_entry
        if host_suspicious:
            report["summary"]["suspicious_hosts"].append(host)

    return report
