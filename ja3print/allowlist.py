"""Simple JSON allowlist support."""
from __future__ import annotations
import json
from pathlib import Path

def load_allowlist(path: str | None) -> set[str]:
    if not path:
        return set()
    p = Path(path)
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        values = data.get("ja3_md5", []) if isinstance(data, dict) else data
        return {str(v).strip().lower() for v in values if str(v).strip()}
    except (OSError, json.JSONDecodeError, AttributeError, TypeError):
        return set()

def add_to_allowlist(path: str, fingerprint: str) -> None:
    p = Path(path)
    data = {"ja3_md5": []}
    if p.exists():
        try:
            loaded = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data["ja3_md5"] = list(loaded.get("ja3_md5", []))
        except Exception:
            pass
    values = set(str(v).lower() for v in data["ja3_md5"])
    values.add(fingerprint.lower())
    data["ja3_md5"] = sorted(values)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
