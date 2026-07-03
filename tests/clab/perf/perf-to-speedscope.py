#!/usr/bin/env python3
"""Convert `perf script` text output to a speedscope sampled profile."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


ADDR_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")
PLUS_RE = re.compile(r"\+0x[0-9a-fA-F]+.*$")


def parse_frame(line: str) -> tuple[str, str] | None:
    s = line.strip()
    if not s:
        return None
    parts = s.split(None, 1)
    if parts and ADDR_RE.match(parts[0]):
        s = parts[1] if len(parts) > 1 else ""
    if not s:
        return None

    file_name = ""
    if " (" in s and s.endswith(")"):
        func, file_name = s.rsplit(" (", 1)
        file_name = file_name[:-1]
    else:
        func = s
    func = PLUS_RE.sub("", func).strip()
    if not func:
        func = "[unknown]"
    return func, file_name


def parse_perf_script(path: Path) -> list[list[tuple[str, str]]]:
    samples: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []

    def flush() -> None:
        nonlocal current
        if not current:
            return
        # perf script prints callchains leaf-first for normal stacks.
        stack = list(reversed(current))
        deduped: list[tuple[str, str]] = []
        for frame in stack:
            if not deduped or deduped[-1] != frame:
                deduped.append(frame)
        samples.append(deduped)
        current = []

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip():
            flush()
            continue
        if raw[0].isspace():
            frame = parse_frame(raw)
            if frame:
                current.append(frame)
        else:
            flush()
    flush()
    return samples


def to_speedscope(samples: list[list[tuple[str, str]]], name: str, sample_rate: float) -> dict[str, Any]:
    frames: list[dict[str, str]] = []
    frame_index: dict[tuple[str, str], int] = {}
    encoded_samples: list[list[int]] = []

    for stack in samples:
        encoded: list[int] = []
        for frame in stack:
            idx = frame_index.get(frame)
            if idx is None:
                idx = len(frames)
                frame_index[frame] = idx
                item = {"name": frame[0]}
                if frame[1]:
                    item["file"] = frame[1]
                frames.append(item)
            encoded.append(idx)
        if encoded:
            encoded_samples.append(encoded)

    weight = 1000.0 / sample_rate if sample_rate > 0 else 1.0
    weights = [weight] * len(encoded_samples)
    return {
        "$schema": "https://www.speedscope.app/file-format-schema.json",
        "exporter": "pproxy tests/clab/perf/perf-to-speedscope.py",
        "name": name,
        "activeProfileIndex": 0,
        "shared": {"frames": frames},
        "profiles": [
            {
                "type": "sampled",
                "name": name,
                "unit": "milliseconds",
                "startValue": 0,
                "endValue": round(sum(weights), 6),
                "samples": encoded_samples,
                "weights": weights,
            }
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="perf script text file")
    ap.add_argument("--output", required=True, help="speedscope JSON output")
    ap.add_argument("--name", default="perf profile")
    ap.add_argument("--sample-rate", type=float, default=99.0)
    args = ap.parse_args()

    samples = parse_perf_script(Path(args.input))
    profile = to_speedscope(samples, args.name, args.sample_rate)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "samples": len(profile["profiles"][0]["samples"]),
        "frames": len(profile["shared"]["frames"]),
        "output": str(out),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
