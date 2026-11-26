"""JSON, CSV and HTML report writers."""
from __future__ import annotations
import csv, json, html
from pathlib import Path

def write_report(records: list[dict], output: str, fmt: str = "json") -> None:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = fmt.lower()
    if fmt == "json":
        path.write_text(json.dumps({"tool": "JA3Print", "version": "2.0.0", "records": records}, indent=2), encoding="utf-8")
    elif fmt == "csv":
        fields = ["timestamp", "handshake_type", "src", "sport", "dst", "dport", "sni", "ja3_string", "ja3_md5", "ja4", "verdict"]
        with path.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)
    elif fmt == "html":
        rows = []
        for r in records:
            cells = [r.get(k, "") for k in ("timestamp", "src", "dst", "sni", "ja3_md5", "ja4", "verdict")]
            rows.append("<tr>" + "".join(f"<td>{html.escape(str(v or ''))}</td>" for v in cells) + "</tr>")
        doc = """<!doctype html><html><head><meta charset="utf-8"><title>JA3Print report</title>
<style>body{font:14px Arial;margin:28px;background:#101827;color:#e7edf5}
h1{color:#76b7ff}table{border-collapse:collapse;width:100%;background:#182437}
th,td{padding:9px;border:1px solid #31435d;text-align:left;overflow-wrap:anywhere}
th{background:#243954}tr:nth-child(even){background:#1d2c42}
.note{color:#b9c7d8}</style></head><body><h1>JA3Print Analysis Report</h1>
<p class="note">Fingerprints are indicators, not proof of malicious activity.</p>
<table><thead><tr><th>Timestamp</th><th>Source</th><th>Destination</th><th>SNI</th>
<th>JA3 MD5</th><th>JA4</th><th>Verdict</th></tr></thead><tbody>""" + "".join(rows) + "</tbody></table></body></html>"
        path.write_text(doc, encoding="utf-8")
    else:
        raise ValueError("Format must be json, csv, or html")
