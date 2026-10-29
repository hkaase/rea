"""Validate every real coordinator job and the recorded parallel execution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from check_evidence import check_bundle, checked


def overlap(left: dict, right: dict) -> float:
    return max(0.0, min(left["finished_monotonic"], right["finished_monotonic"]) - max(left["started_monotonic"], right["started_monotonic"]))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--measurement", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    config = json.loads(args.config.read_text())
    measurement = json.loads(args.measurement.read_text())
    checked(report["status"] == "completed", "Coordinator did not complete all requested jobs")
    checked(measurement["returncode"] == 0, "Coordinator subprocess failed")
    checked(not measurement["surviving_owned_processes"], "Owned processes survived shutdown")
    planned = {job["id"]: job for job in config["jobs"]}
    jobs = {job["id"]: job for job in report["jobs"]}
    checked(set(jobs) == set(planned), "Completed job set differs from the plan")
    results = []
    for name, job in jobs.items():
        checked(job["status"] == "completed", f"{name} did not complete")
        checked(job.get("closed") is True and job.get("evidence_exported") is True, f"{name} did not export and close")
        checked(job["source_sha256_before"] == planned[name]["sha256"] == job["source_sha256_after"], f"{name} source bytes changed")
        checked(job["source_unchanged"] is True, f"{name} source identity was not retained")
        checked(all(not call["reply"]["is_error"] for call in job["calls"]), f"{name} retained a tool error")
        result = check_bundle(Path(report["run_directory"]) / "jobs" / name / "evidence.json", planned[name])
        result["worker"] = job["worker"]
        result["worker_identity"] = job["worker_identity"]
        result["elapsed_seconds"] = job["finished_monotonic"] - job["started_monotonic"]
        results.append(result)
    for worker in {job["worker"] for job in jobs.values()}:
        ordered = sorted((job for job in jobs.values() if job["worker"] == worker), key=lambda job: job["started_monotonic"])
        for previous, following in zip(ordered, ordered[1:]):
            checked(previous["finished_monotonic"] <= following["started_monotonic"], "One worker investigated two targets concurrently")
    p59, e38 = jobs["p59-startup"], jobs["e38-startup"]
    real_overlap = overlap(p59, e38)
    open_overlap = overlap(next(call for call in p59["calls"] if call["tool"] == "open_binary"), next(call for call in e38["calls"] if call["tool"] == "open_binary"))
    analysis_overlap = overlap(next(call for call in p59["calls"] if call["tool"] == "binary_overview"), next(call for call in e38["calls"] if call["tool"] == "binary_overview"))
    java_processes = [process for process in measurement["observed_processes"] if (process.get("executable") or "").endswith("/java")]
    java_overlap = max((max(0.0, min(left["last_seen_seconds"], right["last_seen_seconds"]) - max(left["first_seen_seconds"], right["first_seen_seconds"])) for left in java_processes for right in java_processes if left["ppid"] == p59["worker_identity"]["pid"] and right["ppid"] == e38["worker_identity"]["pid"] and left["pid"] != right["pid"]), default=0.0)
    if config["workers"] > 1:
        checked(p59["worker"] != e38["worker"], "Real images used one worker")
        checked(p59["worker_identity"]["pid"] != e38["worker_identity"]["pid"], "Worker processes were not isolated")
        checked(real_overlap > 0 and analysis_overlap > 0, "Real-image analyses did not overlap")
        checked(java_overlap > 0, "Separate Ghidra JVM lifetimes did not overlap")
        checked(report["peak_active_jobs"] >= 2, "Parallel coordinator never had two active jobs")
    else:
        checked(report["peak_active_jobs"] == 1 and real_overlap == 0, "Serial baseline ran concurrent jobs")
    output = {
        "schema_version": 1, "status": "passed", "report": str(args.report),
        "job_count": len(results), "workers": config["workers"],
        "real_image_job_overlap_seconds": real_overlap,
        "real_image_open_request_overlap_seconds": open_overlap,
        "real_image_analysis_request_overlap_seconds": analysis_overlap,
        "sampled_distinct_worker_jvm_overlap_seconds": java_overlap,
        "elapsed_seconds": measurement["elapsed_seconds"],
        "sampled_peak_process_family_rss_bytes": measurement["sampled_peak_process_family_rss_bytes"],
        "sampled_cpu_seconds_lower_bound": measurement["sampled_cpu_seconds_lower_bound"],
        "cleanup_survivors": len(measurement["surviving_owned_processes"]),
        "jobs": results,
        "limitations": [*measurement["limitations"], "Provider request and sampled Ghidra JVM overlap establish process-level analysis concurrency, not model reasoning concurrency.", "Exited processes can lose /proc executable names before the final sample; JVM-name-based overlap is a lower bound.", "All findings are static observations. Peripheral meanings and complete engine behavior remain unverified."],
    }
    destination = args.output or args.report.parent / "verification.json"
    destination.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"status": "passed", "jobs": len(results), "verification": str(destination), "real_image_overlap_seconds": real_overlap}))


if __name__ == "__main__":
    main()
