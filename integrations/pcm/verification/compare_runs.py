"""Compare equivalent completed serial and parallel static investigations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("parallel", type=Path)
    parser.add_argument("serial", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    parallel = json.loads(args.parallel.read_text())
    serial = json.loads(args.serial.read_text())
    if parallel["status"] != "passed" or serial["status"] != "passed":
        raise ValueError("Both runs must pass their evidence verification")
    parallel_report = json.loads(Path(parallel["report"]).read_text())
    serial_report = json.loads(Path(serial["report"]).read_text())
    parallel_plan = {job["id"]: job["input"] for job in parallel_report["jobs"]}
    serial_plan = {job["id"]: job["input"] for job in serial_report["jobs"]}
    if parallel_plan != serial_plan:
        raise ValueError("Runs did not execute the same investigation jobs and operations")
    result = {
        "schema_version": 1, "status": "passed", "job_count": parallel["job_count"],
        "parallel": {key: parallel[key] for key in ["workers", "elapsed_seconds", "sampled_cpu_seconds_lower_bound", "sampled_peak_process_family_rss_bytes", "real_image_analysis_request_overlap_seconds", "sampled_distinct_worker_jvm_overlap_seconds", "cleanup_survivors"]},
        "serial": {key: serial[key] for key in ["workers", "elapsed_seconds", "sampled_cpu_seconds_lower_bound", "sampled_peak_process_family_rss_bytes", "cleanup_survivors"]},
        "observed_elapsed_serial_divided_by_parallel": serial["elapsed_seconds"] / parallel["elapsed_seconds"],
        "parallel_verification": str(args.parallel), "serial_verification": str(args.serial),
        "limitations": [
            "One measured run per configuration is not a general performance claim.",
            "Both runs use fresh REA worker and Ghidra sessions; operating-system page caches are warm and uncontrolled.",
            "Parallel run precedes serial run; no randomization or confidence interval was measured.",
            "RSS is a sampled process-family sum and can miss between-sample peaks; CPU is a sampled lower bound.",
            "This deterministic pipeline invokes no language model; model-token usage is not applicable.",
            "Throughput measurements do not establish decompiler semantic correctness or controller runtime behavior.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
