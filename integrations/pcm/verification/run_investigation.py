"""Run the real coordinator while measuring its owned Linux process family.

RSS is sampled and is an approximate process-family high-water mark. CPU samples
are a lower bound because a process can exit between samples. No speedup claim is
made without a serial run of the same completed workload.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[1]
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
CLOCK_TICKS = os.sysconf("SC_CLK_TCK")


def process_table() -> dict[int, dict]:
    table = {}
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        try:
            rest = (item / "stat").read_text().rpartition(") ")[2].split()
            try:
                executable = os.readlink(item / "exe")
            except OSError:
                executable = None
            table[int(item.name)] = {
                "pid": int(item.name), "ppid": int(rest[1]), "state": rest[0],
                "executable": executable,
                "start_ticks": int(rest[19]), "cpu_ticks": int(rest[11]) + int(rest[12]),
                "rss_bytes": max(0, int(rest[21])) * PAGE_SIZE,
            }
        except (OSError, ValueError, IndexError):
            continue
    return table


def family(table: dict[int, dict], root: int) -> list[dict]:
    selected = {root}
    changed = True
    while changed:
        changed = False
        for pid, process in table.items():
            if process["ppid"] in selected and pid not in selected:
                selected.add(pid)
                changed = True
    return [table[pid] for pid in selected if pid in table]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    command = [sys.executable, "-m", "coordinator", str(args.config.resolve()), "--output", str((args.output / "run").resolve())]
    started_utc = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    observed = {}
    peak_rss = 0
    peak_processes = 0
    samples = 0
    with (args.output / "stdout.log").open("w") as stdout, (args.output / "stderr.log").open("w") as stderr:
        process = subprocess.Popen(command, cwd=WORKSPACE, stdout=stdout, stderr=stderr)
        while process.poll() is None:
            active = family(process_table(), process.pid)
            peak_rss = max(peak_rss, sum(item["rss_bytes"] for item in active))
            peak_processes = max(peak_processes, len(active))
            for item in active:
                key = (item["pid"], item["start_ticks"])
                previous = observed.get(key, {})
                observed[key] = {**item, "executable": item.get("executable") or previous.get("executable"), "first_seen_seconds": previous.get("first_seen_seconds", time.monotonic() - started), "last_seen_seconds": time.monotonic() - started}
            samples += 1
            time.sleep(0.2)
        returncode = process.wait()
    deadline = time.monotonic() + 5
    survivors = []
    while True:
        table = process_table()
        survivors = [table[pid] for pid, birth in observed if pid in table and table[pid]["start_ticks"] == birth and table[pid]["state"] != "Z"]
        if not survivors or time.monotonic() >= deadline:
            break
        time.sleep(0.2)
    report = {
        "schema_version": 1, "command": command, "started_utc": started_utc,
        "root_pid": process.pid,
        "elapsed_seconds": time.monotonic() - started, "returncode": returncode,
        "sample_period_seconds": 0.2, "samples": samples,
        "sampled_peak_process_family_rss_bytes": peak_rss,
        "sampled_peak_process_count": peak_processes,
        "sampled_cpu_seconds_lower_bound": sum(item["cpu_ticks"] for item in observed.values()) / CLOCK_TICKS,
        "observed_processes": list(observed.values()), "surviving_owned_processes": survivors,
        "limitations": ["Sampled RSS is approximate and can miss between-sample peaks.", "Sampled CPU is a lower bound because exited processes can disappear between samples.", "No model was invoked; agent token usage is not applicable to this deterministic verification run.", "No serial baseline was measured, so this report makes no throughput or speedup claim."],
    }
    (args.output / "measurement.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "returncode": returncode, "elapsed_seconds": report["elapsed_seconds"], "cleanup_survivors": len(survivors)}))
    if returncode:
        raise SystemExit(returncode)
    if survivors:
        raise SystemExit("Coordinator left owned running processes after shutdown")


if __name__ == "__main__":
    main()
