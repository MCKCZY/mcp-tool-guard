"""SSRF protection with IPv4/IPv6 obfuscation decoding, DNS rebinding checks, and domain rules."""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from typing import Callable

from mcp_tool_guard.guards import GuardFinding
from mcp_tool_guard.policy import NetworkPolicy

_METADATA_IPS = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "fd00:ec2::254",
    }
)

_METADATA_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata",
        "metadata.azure.internal",
        "instance-data",
    }
)

_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_NAT64_NET = ipaddress.ip_network("64:ff9b::/96")
_SIXTOFOUR_NET = ipaddress.ip_network("2002::/16")


def _parse_int_part(part: str) -> int | None:
    if not part:
        return None
    low = part.lower()
    try:
        if low.startswith("0x"):
            return int(low, 16)
        if len(low) > 1 and low.startswith("0"):
            return int(low, 8)
        if low.isdigit():
            return int(low, 10)
    except ValueError:
        return None
    return None


def _parse_obfuscated_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Decode standard IPv4/IPv6 plus decimal, hex, octal, shorthand, IPv4-mapped, NAT64, and 6to4 IPs."""
    cleaned = host.strip().strip("[]").split("%", 1)[0].rstrip(".")
    if not cleaned:
        return None

    try:
        ip_obj = ipaddress.ip_address(cleaned)
        return ip_obj
    except ValueError:
        pass

    parts = cleaned.split(".")
    if len(parts) == 1:
        val = _parse_int_part(parts[0])
        if val is not None and 0 <= val <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(val)
        return None

    parsed_parts = [_parse_int_part(p) for p in parts]
    if any(p is None for p in parsed_parts):
        return None
    nums = [int(p) for p in parsed_parts if p is not None]

    if len(nums) == 2:
        a, b = nums
        if 0 <= a <= 255 and 0 <= b <= 0xFFFFFF:
            return ipaddress.IPv4Address((a << 24) | b)
    elif len(nums) == 3:
        a, b, c = nums
        if 0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 0xFFFF:
            return ipaddress.IPv4Address((a << 24) | (b << 16) | c)
    elif len(nums) == 4:
        if all(0 <= x <= 255 for x in nums):
            a, b, c, d = nums
            return ipaddress.IPv4Address((a << 24) | (b << 16) | (c << 8) | d)
    return None


def _extract_embedded_v4(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> list[ipaddress.IPv4Address]:
    if isinstance(ip, ipaddress.IPv4Address):
        return [ip]
    embedded: list[ipaddress.IPv4Address] = []
    if ip.ipv4_mapped is not None:
        embedded.append(ip.ipv4_mapped)
    if ip in _NAT64_NET:
        embedded.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    if ip in _SIXTOFOUR_NET:
        embedded.append(ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF))
    return embedded


def _classify_blocked_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, policy: NetworkPolicy
) -> tuple[str, str] | None:
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [ip]
    candidates.extend(_extract_embedded_v4(ip))

    for addr in candidates:
        s = str(addr)
        if policy.block_metadata_ips and s in _METADATA_IPS:
            return ("SSRF_METADATA_IP_BLOCKED", f"Cloud metadata IP '{s}' is blocked")
        if policy.block_private_ips:
            if (
                addr.is_loopback
                or addr.is_private
                or addr.is_link_local
                or addr.is_multicast
                or addr.is_reserved
                or addr.is_unspecified
                or (isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NET)
            ):
                return (
                    "SSRF_PRIVATE_IP_BLOCKED",
                    f"Non-public/private IP '{s}' is blocked",
                )
    return None


def _domain_matches(host: str, pattern: str) -> bool:
    pat = pattern.lower().lstrip(".")
    h = host.lower().rstrip(".")
    return h == pat or h.endswith(f".{pat}")


def _default_dns_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            ips.append(str(sockaddr[0]))
    return ips


def check_url(
    raw_url: object,
    policy: NetworkPolicy,
    *,
    resolver: Callable[[str], list[str]] | None = None,
) -> list[GuardFinding]:
    """Validate URL scheme, authority, obfuscated IP literals, DNS resolution, and domain rules."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        return [
            GuardFinding(
                guard="ssrf_guard",
                code="INVALID_URL",
                severity="high",
                message="URL must be a non-empty string",
            )
        ]

    if any(ch in raw_url for ch in ("\x00", "\n", "\r", "\t")):
        return [
            GuardFinding(
                guard="ssrf_guard",
                code="URL_CONTROL_CHARS",
                severity="critical",
                message="URL contains control characters",
            )
        ]

    url_str = raw_url.strip()
    if " " in url_str:
        return [
            GuardFinding(
                guard="ssrf_guard",
                code="URL_CONTROL_CHARS",
                severity="critical",
                message="URL contains embedded whitespace",
            )
        ]

    try:
        parsed = urllib.parse.urlsplit(url_str)
    except ValueError as exc:
        return [
            GuardFinding(
                guard="ssrf_guard",
                code="INVALID_URL",
                severity="high",
                message=f"Malformed URL: {exc}",
            )
        ]

    scheme = parsed.scheme.lower()
    allowed_schemes = {s.lower() for s in policy.allowed_schemes}
    if not scheme or scheme not in allowed_schemes:
        return [
            GuardFinding(
                guard="ssrf_guard",
                code="DISALLOWED_URL_SCHEME",
                severity="critical",
                message=f"URL scheme '{scheme or '<empty>'}' is not allowed",
                detail={"scheme": scheme},
            )
        ]

    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return [
            GuardFinding(
                guard="ssrf_guard",
                code="URL_USERINFO_CONFUSION",
                severity="critical",
                message="URL contains embedded userinfo '@' authority confusion",
            )
        ]

    raw_host = parsed.hostname
    if not raw_host:
        return [
            GuardFinding(
                guard="ssrf_guard",
                code="MISSING_URL_HOST",
                severity="high",
                message="URL must contain a valid hostname or IP",
            )
        ]

    host = raw_host.lower().rstrip(".")
    findings: list[GuardFinding] = []

    if (policy.block_private_ips or policy.block_metadata_ips) and (
        host in _METADATA_HOSTNAMES or host.endswith(".localhost") or host.endswith(".internal")
    ):
        findings.append(
            GuardFinding(
                guard="ssrf_guard",
                code="SSRF_INTERNAL_HOST_BLOCKED",
                severity="critical",
                message=f"Internal or metadata hostname '{host}' is blocked",
                detail={"host": host},
            )
        )
        return findings

    if any(_domain_matches(host, d) for d in policy.denied_domains):
        findings.append(
            GuardFinding(
                guard="ssrf_guard",
                code="DENIED_DOMAIN",
                severity="high",
                message=f"Domain '{host}' is in denied_domains",
                detail={"host": host},
            )
        )
        return findings

    ip_literal = _parse_obfuscated_ip(host)
    if ip_literal is not None:
        blocked = _classify_blocked_ip(ip_literal, policy)
        if blocked is not None:
            code, msg = blocked
            findings.append(
                GuardFinding(
                    guard="ssrf_guard",
                    code=code,
                    severity="critical",
                    message=msg,
                    detail={"host": host, "decoded_ip": str(ip_literal)},
                )
            )
            return findings
    elif resolver is not None or policy.resolve_dns:
        fn = resolver or _default_dns_resolver
        try:
            resolved_ips = fn(host)
        except OSError as exc:
            findings.append(
                GuardFinding(
                    guard="ssrf_guard",
                    code="DNS_RESOLUTION_FAILED",
                    severity="high",
                    message=f"DNS resolution failed for '{host}': {exc}",
                    detail={"host": host},
                )
            )
            return findings

        for ip_str in resolved_ips:
            parsed_ip = _parse_obfuscated_ip(ip_str)
            if parsed_ip is None:
                continue
            blocked = _classify_blocked_ip(parsed_ip, policy)
            if blocked is not None:
                code, msg = blocked
                findings.append(
                    GuardFinding(
                        guard="ssrf_guard",
                        code="SSRF_DNS_REBINDING_BLOCKED",
                        severity="critical",
                        message=f"Hostname '{host}' resolved to blocked address ({msg})",
                        detail={"host": host, "resolved_ip": str(parsed_ip)},
                    )
                )
                return findings

    if policy.allowed_domains and not any(
        _domain_matches(host, d) for d in policy.allowed_domains
    ):
        findings.append(
            GuardFinding(
                guard="ssrf_guard",
                code="DOMAIN_NOT_ALLOWLISTED",
                severity="high",
                message=f"Domain '{host}' is not in allowed_domains",
                detail={"host": host},
            )
        )

    return findings
