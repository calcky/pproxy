#!/usr/bin/env python3
"""Merge scenario config_overlay into pproxy JSON (pp1/pp2)."""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path


def set_path(obj: dict, path: str, value):
    parts = path.replace("]", "").split(".")
    cur = obj
    for i, p in enumerate(parts):
        is_last = i == len(parts) - 1
        if "[" in p:
            name, idx_s = p.split("[", 1)
            idx = int(idx_s)
            if name:
                cur = cur.setdefault(name, [])
            if not isinstance(cur, list):
                raise TypeError(f"expected list at {name}[{idx}]")
            while len(cur) <= idx:
                cur.append({})
            if is_last:
                cur[idx] = value
            else:
                if not isinstance(cur[idx], dict):
                    cur[idx] = {}
                cur = cur[idx]
        else:
            if is_last:
                cur[p] = value
            else:
                cur = cur.setdefault(p, {})


def apply_overlay(doc: dict, overlay: dict) -> dict:
    out = copy.deepcopy(doc)
    for key, val in overlay.items():
        set_path(out, key, val)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("overlay_json", help="JSON object of dotted paths -> values")
    args = ap.parse_args()
    src = Path(args.src)
    dst = Path(args.dst)
    overlay = json.loads(args.overlay_json)
    doc = json.loads(src.read_text(encoding="utf-8"))
    merged = apply_overlay(doc, overlay)
    dst.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
