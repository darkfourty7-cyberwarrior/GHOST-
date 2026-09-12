#!/usr/bin/env python3

import socket
import ssl
import json
import os
import re
import sys
import random
import time
import shutil
import urllib.request
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# GHOST@DARK47
# Defensive / Authorized Security Assessment Toolkit
# Made by DARK 47
# ============================================================

RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BOLD = "\033[1m"


# ============================================================
# BLUE MATRIX RAIN STARTUP
# ============================================================

def matrix_rain(duration=3):
    chars = "01ABCDEFGHIJKLMNOPQRSTUVWXYZ#$%&@"

    width = shutil.get_terminal_size((80, 24)).columns
    height = shutil.get_terminal_size((80, 24)).lines

    drops = [
        random.randint(-height, 0)
        for _ in range(width)
    ]

    start_time = time.time()

    hide_cursor = "\033[?25l"
    show_cursor = "\033[?25h"

    try:
        print(hide_cursor, end="")

        while time.time() - start_time < duration:

            print("\033[2J\033[H", end="")

            for row in range(height):
                line = []

                for col in range(width):
                    drop = drops[col]

                    if drop == row:
                        line.append(
                            "\033[96m"
                            + random.choice(chars)
                            + "\033[0m"
                        )

                    elif drop - 1 == row:
                        line.append(
                            "\033[94m"
                            + random.choice(chars)
                            + "\033[0m"
                        )

                    elif drop - 2 == row:
                        line.append(
                            "\033[34m"
                            + random.choice(chars)
                            + "\033[0m"
                        )

                    else:
                        line.append(" ")

                print("".join(line))

            for col in range(width):
                drops[col] += 1

                if drops[col] > height + random.randint(0, 8):
                    drops[col] = random.randint(-10, 0)

            time.sleep(0.05)

    finally:
        print(show_cursor, end="")
        print("\033[2J\033[H", end="")


# ============================================================
# GLOBAL DATA
# ============================================================

LAST_SCAN = {
    "target": None,
    "started": None,
    "finished": None,
    "findings": [],
    "open_ports": [],
    "web": {},
    "tls": {},
    "dns": {},
}


# ============================================================
# UI
# ============================================================

def clear():
    os.system("clear")


def pause():
    input(f"\n{GRAY}Press ENTER to continue...{RESET}")


def banner():
    print(f"""
{CYAN}{BOLD}
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
██║  ███╗███████║██║   ██║███████╗   ██║
██║   ██║██╔══██║██║   ██║╚════██║   ██║
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
{RESET}
{WHITE}{BOLD}
              G H O S T
          S E C U R I T Y
           C O N S O L E
{RESET}
{GRAY}        GHOST@DARK47 Security Toolkit v3.0{RESET}
{CYAN}              Made by DARK 47{RESET}

""")


def section(title):
    print()
    print(f"{CYAN}{BOLD}╔{'═' * 58}╗{RESET}")
    print(f"{CYAN}{BOLD}║ {title:<56} ║{RESET}")
    print(f"{CYAN}{BOLD}╚{'═' * 58}╝{RESET}")


def info(text):
    print(f"{BLUE}[INFO]{RESET} {text}")


def good(text):
    print(f"{GREEN}[OK]{RESET} {text}")


def warn(text):
    print(f"{YELLOW}[WARN]{RESET} {text}")


def danger(text):
    print(f"{RED}[HIGH]{RESET} {text}")


# ============================================================
# TARGET NORMALIZATION
# ============================================================

def normalize_target(target):
    target = target.strip()

    if not target:
        return ""

    target = re.sub(r"^https?://", "", target, flags=re.I)

    target = target.split("/")[0]
    target = target.split("?")[0]
    target = target.split("#")[0]

    if target.count(":") == 1:
        target = target.split(":")[0]

    return target.strip()


def detect_scheme(target):
    target = target.strip()

    if re.match(r"^https://", target, re.I):
        return "https"

    if re.match(r"^http://", target, re.I):
        return "http"

    return None


# ============================================================
# DNS / TARGET RESOLUTION
# ============================================================

def resolve_target(target):
    hostname = normalize_target(target)

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        addresses = sorted(
            set(result[4][0] for result in results)
        )

        return addresses

    except socket.gaierror:
        return []


# ============================================================
# PORT SCANNER
# ============================================================

PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NETBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    2049: "NFS",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}


def check_port(host, port, timeout=0.8):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((host, port))

            if result == 0:
                return port, True

    except Exception:
        pass

    return port, False


def port_scan(target):
    section("PORT & SERVICE SCANNER")

    host = normalize_target(target)

    if not host:
        warn("Invalid target.")
        return []

    addresses = resolve_target(host)

    if not addresses:
        danger("Could not resolve target.")
        return []

    info(f"Target: {host}")
    info(f"Resolved address: {addresses[0]}")
    info(f"Scanning {len(PORTS)} common TCP ports...")

    open_ports = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(check_port, addresses[0], port)
            for port in PORTS
        ]

        for future in as_completed(futures):
            port, is_open = future.result()

            if is_open:
                service = PORTS.get(port, "UNKNOWN")

                open_ports.append({
                    "port": port,
                    "service": service,
                    "protocol": "TCP"
                })

                print(
                    f"{GREEN}[OPEN]{RESET} "
                    f"{port:<5} {service}"
                )

    open_ports.sort(key=lambda x: x["port"])

    if not open_ports:
        good("No common TCP ports detected as open.")

    return open_ports


# ============================================================
# HTTP / WEB SECURITY AUDIT
# ============================================================

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def fetch_url(url):
    headers = {
        "User-Agent": "GHOST@DARK47-Security-Console/3.0"
    }

    request = urllib.request.Request(
        url,
        headers=headers
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=8
        ) as response:

            body = response.read(1024)

            return {
                "success": True,
                "status": response.status,
                "headers": dict(response.headers),
                "url": response.geturl(),
                "sample_bytes": len(body)
            }

    except urllib.error.HTTPError as e:
        return {
            "success": True,
            "status": e.code,
            "headers": dict(e.headers),
            "url": url,
            "sample_bytes": 0
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "headers": {},
            "status": None,
            "url": url
        }


def web_scan(target, scheme=None):
    section("WEB SECURITY AUDIT")

    original = target.strip()

    if scheme is None:
        scheme = detect_scheme(original)

    host = normalize_target(original)

    if not scheme:
        scheme = "https"

    url = f"{scheme}://{host}"

    info(f"URL: {url}")

    result = fetch_url(url)

    if not result["success"]:
        danger(f"Connection failed: {result['error']}")

        return {
            "success": False,
            "findings": [],
            "url": url
        }

    status = result["status"]

    good(f"HTTP status: {status}")

    headers = result.get("headers", {})

    print()
    print(f"{WHITE}{BOLD}Security Headers:{RESET}")

    missing = []

    for header in SECURITY_HEADERS:

        if header in headers:
            good(header)
        else:
            missing.append(header)
            warn(f"Missing: {header}")

    findings = []

    if scheme == "http":
        findings.append({
            "severity": "HIGH",
            "title": "Plain HTTP endpoint",
            "detail": "The tested endpoint uses HTTP instead of HTTPS."
        })

    for header in missing:
        findings.append({
            "severity": "LOW",
            "title": f"Missing security header: {header}",
            "detail": "The response did not contain this recommended security header."
        })

    return {
        "success": True,
        "url": url,
        "status": status,
        "headers": headers,
        "missing_headers": missing,
        "findings": findings
    }


# ============================================================
# TLS / CERTIFICATE AUDIT
# ============================================================

def tls_scan(target):
    section("TLS / CERTIFICATE AUDIT")

    host = normalize_target(target)

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (host, 443),
            timeout=8
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as secure_sock:

                cert = secure_sock.getpeercert()

                version = secure_sock.version()
                cipher = secure_sock.cipher()

                good(f"TLS version: {version}")

                if cipher:
                    info(f"Cipher: {cipher[0]}")

                subject = cert.get("subject", [])
                issuer = cert.get("issuer", [])

                info(f"Certificate subject: {subject}")
                info(f"Certificate issuer: {issuer}")

                return {
                    "success": True,
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else None,
                    "subject": subject,
                    "issuer": issuer,
                }

    except Exception as e:
        danger(f"TLS connection failed: {e}")

        return {
            "success": False,
            "error": str(e)
        }


# ============================================================
# DNS INFORMATION
# ============================================================

def dns_scan(target):
    section("DNS INFORMATION")

    host = normalize_target(target)

    try:
        hostname, aliases, addresses = socket.gethostbyname_ex(host)

        good(f"Hostname: {hostname}")

        if aliases:
            info("Aliases:")

            for alias in aliases:
                print(f"  • {alias}")

        print()
        info("IPv4 addresses:")

        for address in addresses:
            print(f"  • {address}")

        return {
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses
        }

    except Exception as e:
        danger(f"DNS lookup failed: {e}")

        return {
            "success": False,
            "error": str(e)
        }


# ============================================================
# LOCAL NETWORK INFORMATION
# ============================================================

def local_network():
    section("LOCAL NETWORK INFORMATION")

    try:
        hostname = socket.gethostname()

        good(f"Device hostname: {hostname}")

        addresses = socket.gethostbyname_ex(hostname)

        info(f"Local addresses: {addresses[2]}")

        return {
            "hostname": hostname,
            "addresses": addresses[2]
        }

    except Exception as e:
        danger(
            f"Could not determine local network information: {e}"
        )

        return {
            "success": False,
            "error": str(e)
        }


# ============================================================
# RISK ANALYSIS
# ============================================================

def risk_analysis(findings, open_ports):
    section("SECURITY RISK ANALYSIS")

    score = 0
    risks = []

    for finding in findings:

        severity = finding.get("severity", "LOW")

        if severity == "HIGH":
            score += 20

        elif severity == "MEDIUM":
            score += 10

        else:
            score += 2

        risks.append(finding)

    for item in open_ports:

        port = item["port"]

        if port == 23:
            score += 25

            risks.append({
                "severity": "HIGH",
                "title": "Telnet exposed",
                "detail": "Telnet transmits traffic without modern encryption."
            })

        elif port == 445:
            score += 15

            risks.append({
                "severity": "MEDIUM",
                "title": "SMB exposed",
                "detail": "SMB exposure should be restricted to trusted networks."
            })

        elif port == 3389:
            score += 15

            risks.append({
                "severity": "MEDIUM",
                "title": "RDP exposed",
                "detail": "RDP should be protected and restricted."
            })

        elif port == 21:
            score += 10

            risks.append({
                "severity": "MEDIUM",
                "title": "FTP exposed",
                "detail": "Traditional FTP does not provide encrypted transport."
            })

    score = min(score, 100)

    if score >= 70:
        level = "HIGH"

    elif score >= 40:
        level = "MEDIUM"

    else:
        level = "LOW"

    print()
    print(f"{WHITE}{BOLD}Risk Score:{RESET} {score}/100")
    print(f"{WHITE}{BOLD}Risk Level:{RESET} {level}")

    if risks:

        print()
        print(f"{WHITE}{BOLD}Observations:{RESET}")

        for risk in risks:

            severity = risk.get("severity", "LOW")
            title = risk.get("title", "Observation")

            if severity == "HIGH":
                print(f"{RED}• [{severity}] {title}{RESET}")

            elif severity == "MEDIUM":
                print(f"{YELLOW}• [{severity}] {title}{RESET}")

            else:
                print(f"{GRAY}• [{severity}] {title}{RESET}")

    else:
        good("No notable observations from the selected checks.")

    return {
        "score": score,
        "level": level,
        "observations": risks
    }


# ============================================================
# JSON REPORT
# ============================================================

def save_json_report(data):
    filename = "ghost_security_report.json"

    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(
                data,
                file,
                indent=4,
                default=str
            )

        good(f"JSON report saved: {filename}")

    except Exception as e:
        danger(f"Could not save JSON report: {e}")


# ============================================================
# HTML REPORT
# ============================================================

def html_escape(value):
    text = str(value)

    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def save_html_report(data):
    filename = "ghost_security_report.html"

    target = html_escape(data.get("target", ""))

    observations = data.get("risk", {}).get(
        "observations",
        []
    )

    rows = ""

    for item in observations:

        severity = html_escape(
            item.get("severity", "LOW")
        )

        title = html_escape(
            item.get("title", "")
        )

        detail = html_escape(
            item.get("detail", "")
        )

        rows += f"""
        <tr>
            <td>{severity}</td>
            <td>{title}</td>
            <td>{detail}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>GHOST@DARK47 Security Report</title>

<style>
body {{
    background:#080b12;
    color:#e8faff;
    font-family:Arial,sans-serif;
    margin:40px;
}}

h1 {{
    color:#00e5ff;
}}

.card {{
    background:#101722;
    padding:20px;
    margin:20px 0;
    border-radius:10px;
}}

table {{
    width:100%;
    border-collapse:collapse;
}}

th,td {{
    border:1px solid #26313f;
    padding:10px;
    text-align:left;
}}

th {{
    background:#17202c;
}}
</style>
</head>

<body>

<h1>GHOST@DARK47</h1>

<p>Made by DARK 47</p>

<div class="card">
<b>Target:</b> {target}<br>
<b>Started:</b> {html_escape(data.get("started"))}<br>
<b>Finished:</b> {html_escape(data.get("finished"))}
</div>

<div class="card">

<h2>Risk Analysis</h2>

<p>
<b>Score:</b>
{html_escape(data.get("risk", {}).get("score", 0))}/100
</p>

<p>
<b>Level:</b>
{html_escape(data.get("risk", {}).get("level", "UNKNOWN"))}
</p>

</div>

<div class="card">

<h2>Open Ports</h2>

<ul>
"""

    for port in data.get("open_ports", []):

        html += (
            f"<li>{html_escape(port.get('port'))} "
            f"- {html_escape(port.get('service'))}</li>"
        )

    html += """
</ul>

</div>

<div class="card">

<h2>Security Observations</h2>

<table>

<tr>
<th>Severity</th>
<th>Title</th>
<th>Details</th>
</tr>
"""

    html += rows

    html += """
</table>

</div>

</body>
</html>
"""

    try:
        with open(filename, "w", encoding="utf-8") as file:
            file.write(html)

        good(f"HTML report saved: {filename}")

    except Exception as e:
        danger(f"Could not save HTML report: {e}")


# ============================================================
# FULL SCAN
# ============================================================

def full_scan(target):
    global LAST_SCAN

    target = target.strip()

    if not target:
        danger("No target supplied.")
        return

    host = normalize_target(target)

    if not host:
        danger("Invalid target.")
        return

    started = datetime.now().isoformat()

    section("FULL AUTHORIZED SECURITY SCAN")

    print()
    warn(
        "Only scan systems you own or have explicit permission to assess."
    )

    print()

    info(f"Target: {host}")

    addresses = resolve_target(host)

    if addresses:
        info(f"Resolved: {', '.join(addresses)}")

    else:
        danger("Target could not be resolved.")
        return

    open_ports = port_scan(host)

    scheme = detect_scheme(target)

    web = web_scan(target, scheme)

    tls = {}

    if 443 in [x["port"] for x in open_ports]:
        tls = tls_scan(host)

    dns = dns_scan(host)

    findings = []

    if web.get("findings"):
        findings.extend(web["findings"])

    risk = risk_analysis(
        findings,
        open_ports
    )

    finished = datetime.now().isoformat()

    LAST_SCAN = {
        "target": host,
        "started": started,
        "finished": finished,
        "findings": findings,
        "open_ports": open_ports,
        "web": web,
        "tls": tls,
        "dns": dns,
        "risk": risk
    }

    save_json_report(LAST_SCAN)
    save_html_report(LAST_SCAN)

    good("Full scan completed.")


# ============================================================
# REPORT FROM LAST SCAN
# ============================================================

def generate_current_report():
    section("GENERATE CURRENT REPORT")

    if not LAST_SCAN.get("target"):
        warn("No completed scan is available.")
        info("Run option 1 first.")
        return

    save_json_report(LAST_SCAN)
    save_html_report(LAST_SCAN)

    good("Reports regenerated from the latest scan.")


# ============================================================
# MENU
# ============================================================

def menu():

    while True:

        clear()
        banner()

        print(f"{WHITE}{BOLD}GHOST@DARK47 COMMAND CENTER{RESET}\n")

        print(
            f"{CYAN}1{RESET}. Full Authorized Security Scan"
        )

        print(
            f"{CYAN}2{RESET}. Port & Service Scanner"
        )

        print(
            f"{CYAN}3{RESET}. Web Security Audit"
        )

        print(
            f"{CYAN}4{RESET}. TLS / Certificate Audit"
        )

        print(
            f"{CYAN}5{RESET}. DNS Information"
        )

        print(
            f"{CYAN}6{RESET}. Local Network Information"
        )

        print(
            f"{CYAN}7{RESET}. Security Risk Analysis"
        )

        print(
            f"{CYAN}8{RESET}. Generate Current Reports"
        )

        print(
            f"{CYAN}0{RESET}. Exit"
        )

        print()

        choice = input(
            f"{MAGENTA}GHOST@DARK47>{RESET} "
        ).strip()

        if choice == "1":

            target = input(
                "\nTarget domain/IP/URL: "
            ).strip()

            full_scan(target)
            pause()

        elif choice == "2":

            target = input(
                "\nTarget domain/IP: "
            ).strip()

            ports = port_scan(target)

            LAST_SCAN["target"] = normalize_target(target)
            LAST_SCAN["open_ports"] = ports

            pause()

        elif choice == "3":

            target = input(
                "\nTarget hostname or URL: "
            ).strip()

            web = web_scan(target)

            LAST_SCAN["target"] = normalize_target(target)
            LAST_SCAN["web"] = web

            pause()

        elif choice == "4":

            target = input(
                "\nTarget hostname/domain: "
            ).strip()

            tls = tls_scan(target)

            LAST_SCAN["target"] = normalize_target(target)
            LAST_SCAN["tls"] = tls

            pause()

        elif choice == "5":

            target = input(
                "\nTarget hostname/domain: "
            ).strip()

            dns = dns_scan(target)

            LAST_SCAN["target"] = normalize_target(target)
            LAST_SCAN["dns"] = dns

            pause()

        elif choice == "6":

            local_network()
            pause()

        elif choice == "7":

            if not LAST_SCAN.get("target"):
                warn("Run a scan first.")

            else:

                risk = risk_analysis(
                    LAST_SCAN.get("findings", []),
                    LAST_SCAN.get("open_ports", [])
                )

                LAST_SCAN["risk"] = risk

            pause()

        elif choice == "8":

            generate_current_report()
            pause()

        elif choice == "0":

            print()
            good("GHOST@DARK47 shutting down.")
            print()

            sys.exit(0)

        else:

            warn("Invalid option.")
            pause()


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    matrix_rain(3)
    menu()
