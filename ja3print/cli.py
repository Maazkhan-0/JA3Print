"""Command-line interface."""
from __future__ import annotations
import argparse, sys
from pathlib import Path
from . import __version__
from .parser import parse_pcap, PcapReadError
from .fingerprints import build_ja3, build_ja4
from .allowlist import load_allowlist, add_to_allowlist
from .reporting import write_report

def build_parser():
    p = argparse.ArgumentParser(prog="ja3print", description="Defensive TLS ClientHello fingerprint analysis for authorized PCAP files.")
    p.add_argument("pcap", nargs="?", help="Input .pcap or .pcapng capture")
    p.add_argument("-a", "--allowlist", default="data/allowlist.json", help="JA3 MD5 allowlist JSON")
    p.add_argument("-o", "--output", default="reports/ja3print-report.json", help="Report output path")
    p.add_argument("-f", "--format", choices=("json", "csv", "html"), default=None, help="Report format (defaults from output extension)")
    p.add_argument("--include-server-hello", action="store_true", help="Also collect ServerHello packets (JA3S is not calculated in this release)")
    p.add_argument("--add-known", metavar="JA3_MD5", help="Add a manually verified JA3 MD5 to the allowlist and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p

def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.add_known:
        add_to_allowlist(args.allowlist, args.add_known)
        print(f"[+] Added {args.add_known.lower()} to {args.allowlist}")
        return 0
    if not args.pcap:
        build_parser().error("pcap is required unless --add-known is used")
    pcap = Path(args.pcap)
    if not pcap.is_file():
        print(f"[!] Capture file not found: {pcap}", file=sys.stderr)
        return 2
    known = load_allowlist(args.allowlist)
    records = []
    try:
        for item in parse_pcap(str(pcap), include_server_hello=args.include_server_hello):
            if item.handshake_type != "ClientHello":
                records.append({**item.to_dict(), "ja3_string": None, "ja3_md5": None, "ja4": None, "verdict": "SERVER_HELLO_ONLY"})
                continue
            ja3_string, ja3_md5 = build_ja3(item)
            ja4 = build_ja4(item)
            verdict = "KNOWN" if ja3_md5 in known else "UNKNOWN"
            records.append({**item.to_dict(), "ja3_string": ja3_string, "ja3_md5": ja3_md5, "ja4": ja4, "verdict": verdict})
    except PcapReadError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    fmt = args.format or (Path(args.output).suffix.lower().lstrip(".") or "json")
    try:
        write_report(records, args.output, fmt)
    except (OSError, ValueError) as exc:
        print(f"[!] Could not write report: {exc}", file=sys.stderr)
        return 2
    client_count = sum(1 for r in records if r.get("ja3_md5"))
    known_count = sum(1 for r in records if r.get("verdict") == "KNOWN")
    unknown_count = sum(1 for r in records if r.get("verdict") == "UNKNOWN")
    print("\n=== JA3Print Analysis Summary ===")
    print(f"Capture:       {pcap}")
    print(f"ClientHello:   {client_count}")
    print(f"Known:         {known_count}")
    print(f"Unknown:       {unknown_count}")
    print(f"Report:        {args.output}")
    print("Note: UNKNOWN means not present in your local allowlist; it does not mean malicious.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
