#!/usr/bin/env python3
"""Resolve pp1/pp2 JSON paths and apply scenario config_overlay into a temp dir."""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import yaml

_spec = importlib.util.spec_from_file_location(
    "apply_overlay", Path(__file__).resolve().parent / "apply_overlay.py"
)
_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader
_spec.loader.exec_module(_mod)
apply_overlay = _mod.apply_overlay


def resolve_cfg_paths(cfg_dir: Path, tunnel: str, left: str, right: str) -> tuple[Path, Path]:
    cfg_r = "io_uring" if right == "io_uring" else right
    io_right = "kernel_socket" if right == "io_uring" else right
    c1_1 = cfg_dir / f"pp1.{tunnel}.left-{left}.right-{cfg_r}.json"
    c2_1 = cfg_dir / f"pp2.{tunnel}.left-{left}.right-{cfg_r}.json"
    fallbacks = {
        "tcp": ("pp1.json", "pp2.json"),
        "udp": ("pp1.udp.json", "pp2.udp.json"),
        "icmp": ("pp1.icmp.json", "pp2.icmp.json"),
    }
    c1_2 = cfg_dir / fallbacks[tunnel][0]
    c2_2 = cfg_dir / fallbacks[tunnel][1]
    if c1_1.is_file() and c2_1.is_file():
        return c1_1, c2_1
    if c1_2.is_file() and c2_2.is_file():
        return c1_2, c2_2
    raise FileNotFoundError(
        f"no config for tunnel={tunnel} left={left} right={right} in {cfg_dir}"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario-file", required=True)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--base-dir", default="")
    ap.add_argument("--perf-dir", default="")
    args = ap.parse_args()

    scenarios = yaml.safe_load(Path(args.scenario_file).read_text(encoding="utf-8"))
    scen = next((s for s in scenarios if s["name"] == args.scenario), None)
    if not scen:
        raise SystemExit(f"scenario not found: {args.scenario}")

    deploy = scen.get("deploy", {})
    tunnel = deploy.get("tunnel", "udp")
    left = deploy.get("left_io", "tun")
    right = deploy.get("right_io", "kernel_socket")

    clab_dir = Path(__file__).resolve().parent.parent
    perf_dir = Path(args.perf_dir) if args.perf_dir else clab_dir / "config" / "perf"
    base_dir = Path(args.base_dir) if args.base_dir else clab_dir / "config"

    src1 = src2 = None
    for d in (perf_dir, base_dir):
        try:
            src1, src2 = resolve_cfg_paths(d, tunnel, left, right)
            break
        except FileNotFoundError:
            continue
    if not src1:
        raise SystemExit(f"config not found for {tunnel}/{left}/{right}")

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    overlay = scen.get("config_overlay") or {}

    cfg_r = "io_uring" if right == "io_uring" else right
    dst1 = out / f"pp1.{tunnel}.left-{left}.right-{cfg_r}.json"
    dst2 = out / f"pp2.{tunnel}.left-{left}.right-{cfg_r}.json"

    for src, dst in ((src1, dst1), (src2, dst2)):
        doc = json.loads(src.read_text(encoding="utf-8"))
        merged = apply_overlay(doc, overlay)
        dst.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")

    meta = {
        "scenario": args.scenario,
        "deploy": deploy,
        "overlay": overlay,
        "thresholds": scen.get("thresholds") or {},
        "traffic": scen.get("traffic") or {},
        "sources": [str(src1), str(src2)],
    }
    (out / "scenario.meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta))
    return 0


if __name__ == "__main__":
    sys.exit(main())
