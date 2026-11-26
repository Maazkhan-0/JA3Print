"""PCAP reader using Scapy's TLS dissector.

This release analyzes ClientHello/ServerHello packets that Scapy can decode as
complete handshake messages in the capture. TCP stream reassembly is not yet
implemented; fragmented handshakes may be missed and are reported as a limitation.
"""
from __future__ import annotations
from datetime import datetime, timezone
from .fingerprints import HelloData

class PcapReadError(RuntimeError):
    pass

def _first_attr(obj, names, default=None):
    for name in names:
        try:
            value = getattr(obj, name)
            if value is not None:
                return value
        except Exception:
            pass
    return default

def _list_int(value):
    if value is None:
        return []
    if isinstance(value, (bytes, bytearray)):
        return list(value)
    try:
        return [int(x) for x in value]
    except TypeError:
        try:
            return [int(value)]
        except Exception:
            return []

def _ext_type(ext):
    value = _first_attr(ext, ("type", "ext_type"))
    if value is not None:
        try:
            return int(value)
        except Exception:
            pass
    for key in ("type", "ext_type"):
        try:
            value = ext.getfieldval(key)
            if value is not None:
                return int(value)
        except Exception:
            pass
    return None

def _extract_sni(ext):
    try:
        names = _first_attr(ext, ("servernames", "server_name"))
        if names:
            first = names[0]
            value = _first_attr(first, ("servername", "name"))
            if isinstance(value, bytes):
                return value.decode("idna", errors="replace")
            if value:
                return str(value)
    except Exception:
        pass
    return None

def _extract_alpn(ext):
    value = _first_attr(ext, ("protocols", "protocol_name_list", "alpn"))
    result = []
    if value:
        try:
            for item in value:
                if isinstance(item, bytes):
                    result.append(item.decode("ascii", errors="replace"))
                else:
                    raw = _first_attr(item, ("protocol", "protocol_name"))
                    if isinstance(raw, bytes):
                        result.append(raw.decode("ascii", errors="replace"))
                    elif raw:
                        result.append(str(raw))
                    else:
                        result.append(str(item))
        except TypeError:
            pass
    return result

def _extract_extension_values(ext, names):
    return _list_int(_first_attr(ext, names))

def parse_pcap(path: str, include_server_hello: bool = False):
    """Yield HelloData objects from a PCAP/PCAPNG file."""
    try:
        from scapy.utils import PcapReader
        from scapy.layers.tls.all import TLSClientHello, TLSServerHello
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
    except Exception as exc:
        raise PcapReadError("Scapy TLS support is unavailable. Install dependencies with 'python -m pip install -r requirements.txt'.") from exc
    try:
        reader = PcapReader(path)
    except Exception as exc:
        raise PcapReadError(f"Could not open capture file: {exc}") from exc
    try:
        for packet in reader:
            try:
                hello = packet.getlayer(TLSClientHello)
                hello_type = "ClientHello"
                if hello is None and include_server_hello:
                    hello = packet.getlayer(TLSServerHello)
                    hello_type = "ServerHello"
                if hello is None:
                    continue
                ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
                src = getattr(ip_layer, "src", "") if ip_layer else ""
                dst = getattr(ip_layer, "dst", "") if ip_layer else ""
                sport_value = getattr(packet, "sport", None)
                sport = int(sport_value) if sport_value is not None else 0
                dport_value = getattr(packet, "dport", None)
                dport = int(dport_value) if dport_value is not None else 0
                exts = list(_first_attr(hello, ("ext",), []) or [])
                ext_ids, groups, points, versions, sig_algs, alpns = [], [], [], [], [], []
                sni = None
                for ext in exts:
                    etype = _ext_type(ext)
                    if etype is None:
                        continue
                    ext_ids.append(etype)
                    if etype == 10:
                        groups = _extract_extension_values(ext, ("groups", "elliptic_curves"))
                    elif etype == 11:
                        points = _extract_extension_values(ext, ("ecpl", "formats", "point_formats"))
                    elif etype == 43:
                        versions = _extract_extension_values(ext, ("versions", "versionslen"))
                    elif etype == 13:
                        sig_algs = _extract_extension_values(ext, ("sig_algs", "signature_algorithms"))
                    elif etype == 0:
                        sni = _extract_sni(ext)
                    elif etype == 16:
                        alpns = _extract_alpn(ext)
                legacy = int(_first_attr(hello, ("version",), 0) or 0)
                ciphers = _list_int(_first_attr(hello, ("ciphers",), []))
                try:
                    ts = datetime.fromtimestamp(float(packet.time), tz=timezone.utc).isoformat()
                except Exception:
                    ts = None
                yield HelloData(src=src, sport=sport, dst=dst, dport=dport, legacy_version=legacy, ciphers=ciphers, extensions=ext_ids, supported_groups=groups, point_formats=points, supported_versions=versions, signature_algorithms=sig_algs, alpn_protocols=alpns, sni=sni, timestamp=ts, handshake_type=hello_type)
            except Exception:
                continue
    finally:
        reader.close()
