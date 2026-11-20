#!/usr/bin/env python3
"""
port_scanner.py - TCP connect port scanner for CYB Midterm, Part 2.

Scans a list or range of TCP ports on an AUTHORIZED target and reports which
are open or closed. Per the assignment's legal/ethical rules, the scanner only
allows localhost (127.0.0.1) and scanme.nmap.org as targets.

Usage examples:
    python port_scanner.py 127.0.0.1 --common
    python port_scanner.py 127.0.0.1 --range 1-1024
    python port_scanner.py scanme.nmap.org --ports 22,80,443,9929
    python port_scanner.py localhost --ports 21,22,80,443 --delay 0.1
"""

import argparse
import socket
import sys
import time
from datetime import datetime

# Only targets the assignment authorizes. Anything else is refused.
AUTHORIZED_TARGETS = {"127.0.0.1", "localhost", "scanme.nmap.org"}

# A handful of well-known ports and the service usually found there
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-Alt",
}

MAX_PORTS_REMOTE = 100      # Keep remote scans small and polite
DEFAULT_TIMEOUT = 1.0       # Seconds to wait for each connection attempt
DEFAULT_DELAY = 0.05        # Seconds between attempts (rate limiting)
REMOTE_MIN_DELAY = 0.2      # Enforced minimum delay for scanme.nmap.org


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class ScanInputError(ValueError):
    """Raised for invalid user input (bad ports, unauthorized host, etc.)."""


def parse_port(value: str) -> int:
    """Convert a string to a valid port number or raise ScanInputError."""
    try:
        port = int(value)
    except ValueError:
        raise ScanInputError(f"'{value}' is not a valid port number") from None
    if not 1 <= port <= 65535:
        raise ScanInputError(f"Port {port} is out of range (must be 1-65535)")
    return port


def parse_range(text: str) -> list[int]:
    """Turn 'start-end' into a list of ports."""
    if "-" not in text:
        raise ScanInputError(f"Range '{text}' must look like START-END (e.g. 20-100)")
    start_s, end_s = text.split("-", 1)
    start, end = parse_port(start_s.strip()), parse_port(end_s.strip())
    if start > end:
        raise ScanInputError(f"Range start ({start}) is greater than end ({end})")
    return list(range(start, end + 1))


def parse_port_list(text: str) -> list[int]:
    """Turn '22,80,443' into a sorted, de-duplicated list of ports."""
    return sorted({parse_port(p.strip()) for p in text.split(",") if p.strip()})


def validate_target(target: str) -> str:
    """Make sure the target is authorized and resolvable; return its IP."""
    if target.lower() not in AUTHORIZED_TARGETS:
        raise ScanInputError(
            f"Target '{target}' is not authorized. Allowed: "
            + ", ".join(sorted(AUTHORIZED_TARGETS))
        )
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ScanInputError(f"Host '{target}' could not be resolved (unreachable or no DNS)") from None


def scan_port(ip: str, port: int, timeout: float) -> str:
    """
    Attempt a full TCP connection to ip:port.
    Returns 'open', 'closed', or 'filtered' (no reply before the timeout).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))  # 0 means the handshake succeeded
        except socket.timeout:
            return "closed" if ip.startswith("127.") else "filtered"
        except OSError:
            return "error"
    if result == 0:
        return "open"
    # EAGAIN/EWOULDBLOCK/timeout codes behave like a dropped (filtered) packet.
    # Exception: localhost never drops packets, so a slow refusal there is "closed".
    if result in (11, 35, 110, 10035, 10060):
        if ip.startswith("127."):
            return "closed"
        return "filtered"
    return "closed"


def check_host_reachable(ip: str, ports: list[int], timeout: float) -> bool:
    """
    Quick reachability check: try a few ports. A refusal still proves the
    host is up; only timeouts on everything suggest it's unreachable.
    """
    for port in ports[:3]:
        if scan_port(ip, port, timeout) in ("open", "closed"):
            return True
    return False


def run_scan(target: str, ports: list[int], timeout: float, delay: float, show_closed: bool) -> int:
    ip = validate_target(target)
    remote = target.lower() == "scanme.nmap.org"

    if remote:
        if len(ports) > MAX_PORTS_REMOTE:
            raise ScanInputError(
                f"Refusing to scan {len(ports)} ports on {target}; limit is {MAX_PORTS_REMOTE} to stay polite"
            )
        delay = max(delay, REMOTE_MIN_DELAY)

    print("=" * 60)
    print(f" Port Scan Report  |  started {timestamp()}")
    print(f" Target: {target} ({ip})")
    print(f" Ports:  {len(ports)} (from {ports[0]} to {ports[-1]})")
    print(f" Timeout: {timeout}s per port  |  Delay: {delay}s between ports")
    print("=" * 60)

    # Loopback is always "up", so only run the reachability check for remote hosts.
    # (On Windows, closed localhost ports can take ~2s to refuse, which would
    # otherwise look like an unreachable host.)
    if remote and not check_host_reachable(ip, ports, timeout):
        print(f"[{timestamp()}] ERROR: Host {target} ({ip}) appears unreachable "
              "(no response on the first ports tried). Scan aborted.")
        return 2

    start = time.perf_counter()
    counts = {"open": 0, "closed": 0, "filtered": 0, "error": 0}

    for port in ports:
        state = scan_port(ip, port, timeout)
        counts[state] += 1
        service = COMMON_PORTS.get(port, "")
        if state == "open" or show_closed:
            print(f"[{timestamp()}] Port {port:>5}/tcp  {state.upper():<9} {service}")
        time.sleep(delay)  # Rate limiting so we don't hammer the target

    elapsed = time.perf_counter() - start
    print("-" * 60)
    print(f" Finished {timestamp()}  |  elapsed {elapsed:.2f}s "
          f"({elapsed / len(ports):.3f}s per port)")
    print(f" Open: {counts['open']}  Closed: {counts['closed']}  "
          f"Filtered: {counts['filtered']}  Errors: {counts['error']}")
    print("=" * 60)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP connect port scanner (authorized targets only: localhost, scanme.nmap.org)"
    )
    parser.add_argument("target", help="127.0.0.1, localhost, or scanme.nmap.org")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--common", action="store_true", help="Scan common ports (21, 22, 80, 443, ...)")
    group.add_argument("--ports", help="Comma-separated list, e.g. 22,80,443")
    group.add_argument("--range", dest="port_range", help="Port range, e.g. 1-1024")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Seconds per port (default 1.0)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Seconds between ports (default 0.05)")
    parser.add_argument("--open-only", action="store_true", help="Only print open ports")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.timeout <= 0 or args.delay < 0:
            raise ScanInputError("Timeout must be > 0 and delay must be >= 0")
        if args.common:
            ports = sorted(COMMON_PORTS)
        elif args.ports:
            ports = parse_port_list(args.ports)
        else:
            ports = parse_range(args.port_range)
        if not ports:
            raise ScanInputError("No ports to scan")
        return run_scan(args.target, ports, args.timeout, args.delay, not args.open_only)
    except ScanInputError as err:
        print(f"[{timestamp()}] INPUT ERROR: {err}")
        return 1
    except KeyboardInterrupt:
        print(f"\n[{timestamp()}] Scan interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
