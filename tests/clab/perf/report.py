#!/usr/bin/env python3
"""Merge iperf JSON + metrics snapshots into perf result + optional Markdown table."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_iperf(data: dict, proto: str = "tcp") -> dict:
    end = data.get("end", {})
    sum_sent = end.get("sum_sent") or end.get("sum") or {}
    sum_recv = end.get("sum_received") or {}
    if proto == "tcp":
        primary = sum_recv if sum_recv.get("bits_per_second") else sum_sent
    else:
        primary = sum_sent if sum_sent.get("bits_per_second") else sum_recv
    bits = float(primary.get("bits_per_second") or 0)
    mbps = bits / 1e6
    loss = 0.0
    jitter = 0.0
    if proto == "udp" and "sum" in end and isinstance(end["sum"], dict):
        loss = float(end["sum"].get("lost_percent") or 0)
        jitter = float(end["sum"].get("jitter_ms") or 0)
    parallel = int(primary.get("streams") or sum_sent.get("streams") or 1)
    return {
        "proto": proto,
        "parallel": parallel,
        "bitrate_mbps": round(mbps, 3),
        "loss_percent": round(loss, 4),
        "jitter_ms": round(jitter, 4),
    }


def sum_module_events(m: dict, mod_match: str) -> float:
    total = 0.0
    for k, v in m.items():
        if not k.startswith("pp_module_events_out|"):
            continue
        mod = k.split("|", 1)[1]
        if mod_match in mod:
            total += float(v)
    return total


def metrics_delta(before: dict, after: dict) -> dict:
    def sum_module(m: dict, suffix: str) -> float:
        total = 0.0
        for k, v in m.items():
            if k.startswith(f"pp_module_{suffix}|"):
                total += float(v)
        return total

    out: dict[str, Any] = {}
    out["right_tx_out_delta"] = 0.0
    for leaf in ("leaf1", "leaf2"):
        b = before.get(leaf, {})
        a = after.get(leaf, {})
        worker_out = sum_module_events(a, "worker") - sum_module_events(b, "worker")
        right_tx_out = sum_module_events(a, "right_tx") - sum_module_events(b, "right_tx")
        out[leaf] = {
            "events_out_delta": sum_module(a, "events_out") - sum_module(b, "events_out"),
            "drops_delta": sum_module(a, "drops") - sum_module(b, "drops"),
            "worker_out_delta": worker_out,
            "right_tx_out_delta": right_tx_out,
        }
        out["right_tx_out_delta"] += right_tx_out
    out["drops_delta"] = out["leaf1"]["drops_delta"] + out["leaf2"]["drops_delta"]
    return out


def iperf_duration_sec(deploy: dict) -> float:
    return float(deploy.get("duration") or 10)


def pproxy_core_sec_per_s(leaf_cpu: dict) -> float:
    """进程树 CPU 核·秒/秒。新 JSON 为单核基准 %；旧 JSON 为 /ncpu 容量 %。"""
    pproxy = leaf_cpu.get("pproxy") or {}
    if pproxy.get("total_per_core_pct") is not None:
        return float(pproxy["total_per_core_pct"]) / 100.0
    total_pct = float(
        pproxy.get("total_pct") or leaf_cpu.get("process_cpu_avg_pct") or 0
    )
    ncpu = int(leaf_cpu.get("ncpu") or 1)
    return total_pct / 100.0 * ncpu


def compute_pps_cpp(result: dict) -> dict[str, Any]:
    """PPS + cpp(pp) = pproxy core-µs per worker-forwarded packet."""
    duration = iperf_duration_sec(result.get("deploy") or {})
    delta = result.get("metrics_delta") or {}
    cpu = result.get("cpu") or {}
    total_pkts = float(delta.get("right_tx_out_delta") or 0)
    pps = total_pkts / duration if duration > 0 else 0.0

    cpp_pp: dict[str, float | None] = {}
    for leaf in ("leaf1", "leaf2"):
        leaf_pps = leaf_worker_pps(leaf, delta, total_pkts, duration)
        leaf_cpu = cpu.get(leaf) or {}
        pp_sec = pproxy_core_sec_per_s(leaf_cpu)
        cpp_pp[leaf] = cpp_from_core_sec(pp_sec, leaf_pps)

    return {
        "pps": round(pps, 1),
        "cpp": cpp_pp,
        "cpp_pp": cpp_pp,
    }


def leaf_worker_pps(
    leaf: str, delta: dict, total_pkts: float, duration: float
) -> float:
    leaf_delta = delta.get(leaf) or {}
    pkts = leaf_delta.get("worker_out_delta")
    if pkts is None:
        pkts = leaf_delta.get("right_tx_out_delta")
    if pkts is None and total_pkts > 0:
        pkts = total_pkts / 2.0
    pkts = float(pkts or 0)
    return pkts / duration if duration > 0 else 0.0


def cpp_from_core_sec(core_sec: float, leaf_pps: float) -> float | None:
    if leaf_pps > 0 and core_sec > 0:
        return round(core_sec * 1e6 / leaf_pps, 1)
    return None

def fmt_pps(pps: float) -> str:
    if pps <= 0:
        return "-"
    if pps >= 1_000_000:
        return f"{pps / 1e6:.2f}M"
    if pps >= 10_000:
        return f"{pps / 1e3:.1f}k"
    return f"{pps:.0f}"


def fmt_cpp(cpp: float | None) -> str:
    if cpp is None:
        return "-"
    return f"{cpp:.1f}"


def check_thresholds(iperf: dict, thresholds: dict) -> list[str]:
    errs = []
    if not thresholds:
        return errs
    min_mbps = thresholds.get("min_mbps")
    if min_mbps is not None and iperf.get("bitrate_mbps", 0) < float(min_mbps):
        errs.append(f"bitrate {iperf['bitrate_mbps']} Mbps < min {min_mbps}")
    max_loss = thresholds.get("max_loss_pct")
    if max_loss is not None and iperf.get("proto") == "udp":
        if iperf.get("loss_percent", 0) > float(max_loss):
            errs.append(f"loss {iperf['loss_percent']}% > max {max_loss}%")
    return errs


def _leaf_cpu_block(leaf: dict | None) -> dict[str, Any]:
    if not leaf or leaf.get("error"):
        return {}
    pproxy = leaf.get("pproxy") or {}
    if not pproxy and leaf.get("process_cpu_avg_pct") is not None:
        total = float(leaf["process_cpu_avg_pct"])
        pproxy = {"total_pct": total, "user_pct": total, "sys_pct": 0.0}
    return {
        "pproxy": pproxy,
        "system": leaf.get("system") or {},
        "threads": leaf.get("threads") or {},
    }


def fmt_system_top(system: dict) -> str:
    """Format us/sy/si/id from /proc/stat window (sum ≤ 100%)."""
    if not system:
        return "-"
    fields = (
        ("user_pct", "us"),
        ("system_pct", "sy"),
        ("softirq_pct", "si"),
        ("idle_pct", "id"),
    )
    parts = [f"{float(system.get(key, 0) or 0):.1f} {label}" for key, label in fields]
    return ", ".join(parts)


def fmt_leaf_cpu_cols(leaf_raw: dict | None) -> tuple[str, str]:
    """Return (pproxy, system top line) for one leaf."""
    cell = _leaf_cpu_block(leaf_raw)
    if not cell:
        return "-", "-"
    p = cell.get("pproxy") or {}
    s = cell.get("system") or {}
    if p:
        pp = f"{p.get('total_pct', 0):.1f} (u{p.get('user_pct', 0):.1f}/s{p.get('sys_pct', 0):.1f})"
    else:
        pp = "-"
    return pp, fmt_system_top(s)


def markdown_row(result: dict) -> str:
    i = result.get("iperf", {})
    d = result.get("deploy", {})
    cpu = result.get("cpu") or {}
    l1 = _leaf_cpu_block(cpu.get("leaf1"))
    l2 = _leaf_cpu_block(cpu.get("leaf2"))
    return (
        f"| {result.get('scenario', '?')} | {d.get('right_io', '?')} | "
        f"{d.get('batch_tx', '-')} | {i.get('parallel', '-')} | "
        f"{i.get('bitrate_mbps', 0)} | {result.get('metrics_delta', {}).get('drops_delta', 0)} |"
    )


def matrix_markdown_row(result: dict, json_name: str = "") -> str:
    i = result.get("iperf", {})
    d = result.get("deploy", {})
    cpu = result.get("cpu") or {}
    pc = result.get("pps_cpp") or compute_pps_cpp(result)
    l1 = fmt_leaf_cpu_cols(cpu.get("leaf1"))
    l2 = fmt_leaf_cpu_cols(cpu.get("leaf2"))
    cpp_pp = pc.get("cpp_pp") or pc.get("cpp") or {}
    return (
        f"| {result.get('scenario', '?')} | {d.get('right_io', '?')} | "
        f"{i.get('parallel', '-')} | {i.get('bitrate_mbps', 0)} | "
        f"{fmt_pps(float(pc.get('pps') or 0))} | "
        f"{l1[0]} | {l1[1]} | {fmt_cpp(cpp_pp.get('leaf1'))} | "
        f"{l2[0]} | {l2[1]} | {fmt_cpp(cpp_pp.get('leaf2'))} |"
    )


def matrix_md_header(started: str) -> str:
    headers = [
        "scenario", "right_io", "P", "Mbps", "PPS",
        "L1 pp", "L1 sys", "L1 core-us",
        "L2 pp", "L2 sys", "L2 core-us",
    ]
    hdr = "| " + " | ".join(headers) + " |"
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    return f"# pproxy perf matrix\n\nStarted: {started}\n\n{hdr}\n{sep}\n"


def append_doc(doc_path: Path, rows: list[str]) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    block = [
        "",
        f"## Run {ts}",
        "",
        "| scenario | right_io | batch_tx | parallel | Mbps | drops |",
        "|----------|----------|----------|----------|------|-------|",
        *rows,
        "",
    ]
    with doc_path.open("a", encoding="utf-8") as f:
        f.write("\n".join(block))


def update_matrix_md(md_path: Path, result: dict, json_name: str) -> None:
    row = matrix_markdown_row(result, json_name)
    if not md_path.is_file():
        started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        md_path.write_text(matrix_md_header(started) + row + "\n", encoding="utf-8")
        return
    with md_path.open("a", encoding="utf-8") as f:
        f.write(row + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--deploy-json", required=True, help="JSON deploy metadata")
    ap.add_argument("--iperf", required=True, help="iperf3 -J output file")
    ap.add_argument("--metrics-before", required=True)
    ap.add_argument("--metrics-after", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--thresholds-json", default="{}")
    ap.add_argument("--baseline-direct-mbps", type=float, default=None)
    ap.add_argument("--mode", default="pproxy")
    ap.add_argument("--iperf-proto", default="tcp")
    ap.add_argument("--cpu", default="", help="CPU sample JSON from collect-cpu.sh")
    ap.add_argument("--update-doc", default="")
    ap.add_argument("--matrix-md", default="", help="matrix*.md path; append row after each run")
    ap.add_argument("--fail-on-threshold", action="store_true")
    args = ap.parse_args()

    iperf_raw = json.loads(Path(args.iperf).read_text(encoding="utf-8"))
    before = json.loads(Path(args.metrics_before).read_text(encoding="utf-8"))
    after = json.loads(Path(args.metrics_after).read_text(encoding="utf-8"))
    deploy = json.loads(args.deploy_json)
    thresholds = json.loads(args.thresholds_json)

    iperf = parse_iperf(iperf_raw, args.iperf_proto)
    if deploy.get("parallel"):
        iperf["parallel"] = int(deploy["parallel"])
    delta = metrics_delta(before, after)
    result: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scenario": args.scenario,
        "mode": args.mode,
        "deploy": deploy,
        "iperf": iperf,
        "metrics_delta": delta,
        "thresholds": thresholds,
    }
    if args.baseline_direct_mbps is not None and args.baseline_direct_mbps > 0:
        result["baseline_direct_mbps"] = args.baseline_direct_mbps
        result["efficiency_pct"] = round(
            100.0 * iperf["bitrate_mbps"] / args.baseline_direct_mbps, 2
        )
    if args.cpu:
        cpu_path = Path(args.cpu)
        if cpu_path.is_file():
            result["cpu"] = json.loads(cpu_path.read_text(encoding="utf-8"))

    result["pps_cpp"] = compute_pps_cpp(result)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))

    if args.update_doc:
        append_doc(Path(args.update_doc), [markdown_row(result)])

    if args.matrix_md:
        update_matrix_md(Path(args.matrix_md), result, out_path.name)

    if args.fail_on_threshold:
        errs = check_thresholds(iperf, thresholds)
        if errs:
            print("THRESHOLD FAIL:", "; ".join(errs), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
