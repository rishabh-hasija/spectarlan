from __future__ import annotations

import concurrent.futures
import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

import psutil

from .models import Device


MAX_SCAN_HOSTS = 256


def _private_ipv4_candidates() -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    stats = psutil.net_if_stats()

    for name, addrs in psutil.net_if_addrs().items():
        if name in stats and not stats[name].isup:
            continue
        for addr in addrs:
            if addr.family != socket.AF_INET or not addr.netmask:
                continue
            ip = ipaddress.ip_address(addr.address)
            if ip.is_loopback or not ip.is_private:
                continue
            candidates.append((addr.address, addr.netmask))
    return candidates


def detect_local_network() -> tuple[str, str]:
    candidates = _private_ipv4_candidates()
    if not candidates:
        raise RuntimeError("No active private IPv4 interface found.")

    # Prefer common LAN ranges over virtual adapters when possible.
    def score(item: tuple[str, str]) -> tuple[int, int]:
        ip_s, mask = item
        ip = ipaddress.ip_address(ip_s)
        preferred = int(
            ip in ipaddress.ip_network("192.168.0.0/16")
            or ip in ipaddress.ip_network("10.0.0.0/8")
            or ip in ipaddress.ip_network("172.16.0.0/12")
        )
        prefix = ipaddress.ip_network(f"{ip_s}/{mask}", strict=False).prefixlen
        return preferred, prefix

    local_ip, netmask = sorted(candidates, key=score, reverse=True)[0]
    discovered = ipaddress.ip_network(f"{local_ip}/{netmask}", strict=False)

    # Keep scans small and local. A broad corporate/VPN range is capped to the
    # /24 containing the current machine.
    if discovered.num_addresses > MAX_SCAN_HOSTS:
        discovered = ipaddress.ip_network(f"{local_ip}/24", strict=False)

    validate_scan_scope(str(discovered), local_ip)
    return local_ip, str(discovered)


def validate_scan_scope(network: str, local_ip: str) -> None:
    net = ipaddress.ip_network(network, strict=False)
    ip = ipaddress.ip_address(local_ip)

    if net.version != 4 or ip.version != 4:
        raise ValueError("SpecterLAN MVP supports IPv4 only.")
    if not net.is_private:
        raise ValueError("Only private networks are allowed.")
    if ip not in net:
        raise ValueError("Scan target must contain this machine's local IP.")
    if net.num_addresses > MAX_SCAN_HOSTS:
        raise ValueError(f"Scan is limited to {MAX_SCAN_HOSTS} addresses.")


def classify_device(hostname: str | None, vendor: str | None) -> str:
    text = f"{hostname or ''} {vendor or ''}".lower()

    groups = [
        ("router", ("router", "gateway", "fritz", "ubiquiti", "netgear", "tp-link", "asus")),
        ("printer", ("printer", "epson", "brother", "canon", "xerox", "laserjet")),
        ("tv", ("tv", "roku", "chromecast", "hisense", "samsung electronics", "lg electronics")),
        ("phone", ("iphone", "android", "pixel", "oneplus", "xiaomi", "oppo")),
        ("computer", ("desktop", "laptop", "macbook", "windows", "raspberry", "intel")),
        ("iot", ("esp", "tuya", "sonos", "amazon technologies", "google home", "nest")),
    ]
    for category, markers in groups:
        if any(marker in text for marker in markers):
            return category
    return "unknown"


def _scan_with_nmap(network: str) -> list[Device]:
    proc = subprocess.run(
        ["nmap", "-sn", "-oX", "-", network],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Nmap host discovery failed.")

    root = ET.fromstring(proc.stdout)
    devices: list[Device] = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue

        ipv4 = None
        mac = None
        vendor = None
        for address in host.findall("address"):
            kind = address.attrib.get("addrtype")
            if kind == "ipv4":
                ipv4 = address.attrib.get("addr")
            elif kind == "mac":
                mac = address.attrib.get("addr")
                vendor = address.attrib.get("vendor")

        if not ipv4:
            continue

        hostname = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            first = hostnames.find("hostname")
            if first is not None:
                hostname = first.attrib.get("name")

        devices.append(
            Device(
                ip=ipv4,
                hostname=hostname,
                mac=mac,
                vendor=vendor,
                device_type=classify_device(hostname, vendor),
            )
        )
    return devices


def _ping(ip: str) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "350", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
    )
    return proc.returncode == 0


def _arp_table() -> dict[str, str]:
    commands = [["arp", "-a"]]
    if platform.system().lower() != "windows":
        commands.insert(0, ["ip", "neigh"])

    output = ""
    for cmd in commands:
        if shutil.which(cmd[0]):
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.stdout:
                output += "\n" + proc.stdout

    pairs: dict[str, str] = {}
    ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    mac_pattern = r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"

    for line in output.splitlines():
        ip_match = re.search(ip_pattern, line)
        mac_match = re.search(mac_pattern, line)
        if ip_match and mac_match:
            pairs[ip_match.group(0)] = mac_match.group(0).upper().replace("-", ":")
    return pairs


def _scan_with_ping(network: str) -> list[Device]:
    net = ipaddress.ip_network(network, strict=False)
    hosts = [str(ip) for ip in net.hosts()]

    live: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        future_map = {pool.submit(_ping, ip): ip for ip in hosts}
        for future in concurrent.futures.as_completed(future_map):
            ip = future_map[future]
            try:
                if future.result():
                    live.append(ip)
            except Exception:
                pass

    arp = _arp_table()
    devices: list[Device] = []
    for ip in sorted(live, key=lambda value: ipaddress.ip_address(value)):
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except OSError:
            pass
        devices.append(
            Device(
                ip=ip,
                hostname=hostname,
                mac=arp.get(ip),
                vendor=None,
                device_type=classify_device(hostname, None),
            )
        )
    return devices


def discover(network: str, local_ip: str) -> tuple[list[Device], str]:
    validate_scan_scope(network, local_ip)

    if shutil.which("nmap"):
        return _scan_with_nmap(network), "nmap -sn"

    return _scan_with_ping(network), "ping + neighbor table fallback"
