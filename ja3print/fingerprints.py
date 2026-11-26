"""Fingerprint algorithms. Pure functions are deliberately separated from PCAP parsing."""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, asdict

def is_grease(value: int) -> bool:
    """Return True for GREASE values (RFC 8701 pattern)."""
    return (value & 0x0F0F) == 0x0A0A and ((value >> 8) & 0xFF) == (value & 0xFF)

def _clean(values):
    return [int(v) for v in (values or []) if v is not None and not is_grease(int(v))]

def _csv(values):
    return "-".join(str(v) for v in values)

@dataclass
class HelloData:
    src: str = ""
    sport: int = 0
    dst: str = ""
    dport: int = 0
    legacy_version: int = 0
    ciphers: list[int] | None = None
    extensions: list[int] | None = None
    supported_groups: list[int] | None = None
    point_formats: list[int] | None = None
    supported_versions: list[int] | None = None
    signature_algorithms: list[int] | None = None
    alpn_protocols: list[str] | None = None
    sni: str | None = None
    timestamp: str | None = None
    handshake_type: str = "ClientHello"

    def to_dict(self):
        return asdict(self)

def build_ja3(data: HelloData) -> tuple[str, str]:
    """Return JA3 raw string and its lowercase MD5 digest."""
    version = int(data.legacy_version or 0)
    ciphers = _clean(data.ciphers)
    extensions = _clean(data.extensions)
    groups = _clean(data.supported_groups)
    points = _clean(data.point_formats)
    raw = ",".join([str(version), _csv(ciphers), _csv(extensions), _csv(groups), _csv(points)])
    return raw, hashlib.md5(raw.encode("utf-8")).hexdigest()

def _ja4_version(data: HelloData) -> str:
    versions = _clean(data.supported_versions)
    version = max(versions) if versions else int(data.legacy_version or 0)
    mapping = {0x0304:"13",0x0303:"12",0x0302:"11",0x0301:"10",0x0300:"s3",0x0002:"s2",0xFEFF:"d1",0xFEFD:"d2",0xFEFC:"d3"}
    return mapping.get(version, "00")

def _two_digit_count(count: int) -> str:
    return f"{min(count, 99):02d}"

def build_ja4(data: HelloData, transport: str = "t") -> str:
    """Build JA4 for TLS-over-TCP ClientHello data (not QUIC/DTLS capture decoding)."""
    ciphers = _clean(data.ciphers)
    extensions = _clean(data.extensions)
    sni_flag = "d" if data.sni else "i"
    alpn = data.alpn_protocols or []
    alpn_label = alpn[0][0] + alpn[0][-1] if alpn and alpn[0] else "00"
    part_a = f"{transport}{_ja4_version(data)}{sni_flag}{_two_digit_count(len(ciphers))}{_two_digit_count(len(extensions))}{alpn_label}"
    cipher_text = ",".join(f"{value:04x}" for value in sorted(ciphers))
    part_b = hashlib.sha256(cipher_text.encode()).hexdigest()[:12] if cipher_text else "000000000000"
    ext_for_hash = sorted(v for v in extensions if v not in (0x0000, 0x0010))
    ext_text = ",".join(f"{value:04x}" for value in ext_for_hash)
    sig_text = ",".join(f"{value:04x}" for value in _clean(data.signature_algorithms))
    if not ext_text:
        part_c = "000000000000"
    else:
        hash_input = ext_text + (("_" + sig_text) if sig_text else "")
        part_c = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
    return f"{part_a}_{part_b}_{part_c}"
