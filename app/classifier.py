import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from app.schemas import IOCType


class InvalidIOC(ValueError):
    """Raised when input is malformed or unsupported."""


@dataclass(frozen=True)
class ClassifiedIOC:
    value: str
    type: IOCType


CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$", re.IGNORECASE)
HASH_RE = re.compile(r"^[0-9a-fA-F]+$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def _ascii_hostname(value: str) -> str:
    try:
        return value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidIOC("IOC contains an invalid internationalized hostname") from exc


def classify_ioc(raw: str) -> ClassifiedIOC:
    value = raw.strip()
    if not value or len(value) > 2048 or any(ord(char) < 32 for char in value):
        raise InvalidIOC("IOC is empty, too long, or contains control characters")

    if CVE_RE.fullmatch(value):
        return ClassifiedIOC(value.upper(), IOCType.CVE)

    try:
        ip = ipaddress.ip_address(value)
        return ClassifiedIOC(ip.compressed, IOCType.IPV4 if ip.version == 4 else IOCType.IPV6)
    except ValueError:
        pass

    parts = urlsplit(value)
    if parts.scheme:
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise InvalidIOC("Only valid HTTP and HTTPS URLs are supported")
        if parts.username or parts.password:
            raise InvalidIOC("URLs containing embedded credentials are not supported")
        host = _ascii_hostname(parts.hostname)
        try:
            parsed_port = parts.port
        except ValueError as exc:
            raise InvalidIOC("URL contains an invalid port") from exc
        default_port = (parts.scheme.lower(), parsed_port) in {("http", 80), ("https", 443)}
        port = f":{parsed_port}" if parsed_port and not default_port else ""
        canonical = urlunsplit((parts.scheme.lower(), host + port, parts.path or "/", parts.query, ""))
        return ClassifiedIOC(canonical, IOCType.URL)

    if HASH_RE.fullmatch(value):
        hash_types = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}
        if len(value) in hash_types:
            return ClassifiedIOC(value.lower(), hash_types[len(value)])

    ascii_domain = _ascii_hostname(value.rstrip("."))
    if DOMAIN_RE.fullmatch(ascii_domain):
        return ClassifiedIOC(ascii_domain, IOCType.DOMAIN)
    raise InvalidIOC("Unsupported or malformed IOC")
