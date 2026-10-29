"""Bounded worker pool. Each REA session owns one serially accessed Program.

The pool performs static investigations only. It preserves complete REA Evidence
alongside a small finding ledger, and never treats pseudocode as runtime proof.
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import time
from typing import Any
import uuid

STATIC_TOOLS = frozenset({
    "binary_overview", "list_procedures", "list_names", "list_segments", "list_strings",
    "search_procedures", "search_names", "search_strings", "analyze_function",
    "inspect_native_load_image", "inspect_native_instruction", "inspect_native_data_type",
    "resolve_native_call_targets", "read_function_instructions", "read_bytes",
    "procedure_assembly", "procedure_pseudo_code", "procedure_info", "procedure_references",
    "procedure_callees", "procedure_callers", "procedure_address", "xrefs",
    "inspect_analysis_view", "inspect_native_api", "find_xrefs_to_name", "binary_session",
})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
        stream.flush()
    temporary.replace(path)


def validate_config(config: dict, base: Path | None = None) -> dict:
    """Normalize explicit caller configuration; never infer a CPU from .bin."""
    config = json.loads(json.dumps(config, allow_nan=False))
    if config.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    workers = config.get("workers", 2)
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError("workers must be a positive integer")
    config["workers"] = workers
    if not isinstance(config.get("rea", {}).get("command"), str):
        raise ValueError("rea.command must select an executable")
    if not all(isinstance(arg, str) for arg in config["rea"].get("args", [])):
        raise ValueError("rea.args must contain strings")
    if not isinstance(config.get("jobs"), list) or not config["jobs"]:
        raise ValueError("jobs must be a nonempty list")
    for key, default in [("startup_timeout", 120), ("call_timeout", 600), ("cleanup_timeout", 60)]:
        value = config.get(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"{key} must be a positive finite number")
        config[key] = value
    ids = set()
    for job in config["jobs"]:
        if not isinstance(job.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", job["id"]):
            raise ValueError("job id must be a safe, nonempty filename component")
        if job["id"] in ids:
            raise ValueError(f"Duplicate job id: {job['id']}")
        ids.add(job["id"])
        path = Path(job["path"]).expanduser()
        if not path.is_absolute():
            path = (base or Path.cwd()) / path
        job["path"] = str(path.resolve())
        if not re.fullmatch(r"[0-9a-f]{64}", job.get("sha256", "")):
            raise ValueError("Every job requires its expected lowercase sha256")
        if job.get("architecture") not in {"cpu32", "powerpc"}:
            raise ValueError("Firmware architecture must be cpu32 or powerpc")
        for field in ["entry_point", *(["load_address"] if "load_address" in job else [])]:
            if not re.fullmatch(r"0x[0-9A-Fa-f]{1,8}", job.get(field, "")):
                raise ValueError(f"{field} must be an explicit 32-bit hexadecimal address")
            job[field] = hex(int(job[field], 16))
        alignment = 2 if job["architecture"] == "cpu32" else 4
        if int(job["entry_point"], 16) % alignment:
            raise ValueError("Execution entry is not instruction-aligned")
        job.setdefault("questions", [])
        if not all(isinstance(q, str) and q for q in job["questions"]):
            raise ValueError("questions must contain nonempty strings")
        job.setdefault("operations", [])
        if not isinstance(job["operations"], list):
            raise ValueError("operations must be a list")
        for operation in job["operations"]:
            if operation.get("tool") not in STATIC_TOOLS:
                raise ValueError(f"Operation is outside the static investigation surface: {operation.get('tool')}")
            if not isinstance(operation.get("arguments", {}), dict):
                raise ValueError("Tool arguments must be an object")
    return config


def load_config(path: str | Path) -> dict:
    path = Path(path).resolve()
    return validate_config(json.loads(path.read_text()), path.parent)


def decode_reply(result) -> dict:
    structured = result.structuredContent
    if structured is None:
        text = "\n".join(block.text for block in result.content if block.type == "text")
        try:
            structured = json.loads(text)
        except json.JSONDecodeError:
            structured = {"text": text}
    return {"is_error": bool(result.isError), "structured": structured}


class ToolFailure(RuntimeError):
    pass


def verify_reply_binding(tool: str, value: dict, report: dict) -> None:
    """Reject cross-target or changing-profile replies before deriving findings."""
    job = report["input"]
    if tool in {"open_binary", "binary_session"}:
        target = value.get("result", {})
        for key in ["sha256", "architecture", "entry_point"]:
            if target.get(key) != job[key]:
                raise ToolFailure(f"{tool} target binding disagrees on {key}")
        if "load_address" in job and target.get("load_address") != job["load_address"]:
            raise ToolFailure(f"{tool} target binding disagrees on load_address")
        if "load_address" not in job and target.get("load_address", job["entry_point"]) != job["entry_point"]:
            raise ToolFailure(f"{tool} legacy target binding changed the load address")
    if "evidence_id" not in value:
        return
    subject = value.get("subject") or {}
    if subject.get("digest", {}).get("sha256") != job["sha256"]:
        raise ToolFailure(f"{tool} Evidence belongs to another source image")
    provider = value.get("provider", {}).get("id")
    profile = value.get("analysis_profile")
    registry = report.setdefault("analysis_profiles", {})
    if profile is None and provider == "rea-analysis-view":
        projection = value.get("normalized_result") or {}
        source_digest = projection.get("source_analysis_profile_digest")
        profile = registry.get(source_digest)
        if profile is None:
            raise ToolFailure(f"{tool} summary cites an unbound source analysis profile")
        if profile.get("provider") != projection.get("source_provider"):
            raise ToolFailure(f"{tool} summary source provider disagrees with its bound profile")
        parent = projection.get("parent_evidence_id")
        if (not isinstance(parent, str) or parent != value.get("parameters", {}).get("parent_evidence_id")
                or parent not in value.get("evidence_links", [])
                or parent != "ev_" + str(projection.get("parent_digest"))):
            raise ToolFailure(f"{tool} summary does not preserve its parent Evidence link")
        if projection.get("artifact", {}).get("sha256") != job["sha256"]:
            raise ToolFailure(f"{tool} summary artifact belongs to another image")
        report.setdefault("projection_sources", []).append({"evidence_id": value["evidence_id"],
            "parent_evidence_id": parent, "source_analysis_profile_digest": source_digest})
        provider = projection["source_provider"]["id"]
    profile = profile or {}
    if not profile.get("digest"):
        raise ToolFailure(f"{tool} Evidence has no analysis-profile identity")
    # REA enhanced observations carry a composed workflow profile containing
    # the provider's upstream commitment. Keep every original digest; a
    # workflow digest is not interchangeable with the engine commitment.
    if provider != profile.get("provider", {}).get("id"):
        raise ToolFailure(f"{tool} Evidence/profile provider identities disagree")
    registry[profile["digest"]] = profile
    report.setdefault("analysis_profile_digests", [])
    if profile["digest"] not in report["analysis_profile_digests"]:
        report["analysis_profile_digests"].append(profile["digest"])
    if provider == "rea-workflow":
        profile = profile.get("parameters", {}).get("upstream_analysis_profile") or {}
    if profile.get("provider", {}).get("id") != "ghidra":
        raise ToolFailure(f"{tool} Evidence is not backed by a Ghidra analysis profile")
    engine = profile.get("provider", {})
    registry[profile["digest"]] = profile
    previous_engine = report.setdefault("engine_identity", engine)
    if engine != previous_engine:
        raise ToolFailure(f"{tool} changed its concrete Ghidra engine identity")
    report.setdefault("engine_profile_digests", [])
    if profile.get("digest") not in report["engine_profile_digests"]:
        report["engine_profile_digests"].append(profile.get("digest"))
    parameters = profile.get("parameters", {})
    language = {"cpu32": "68000:BE:32:CPU32", "powerpc": "PowerPC:BE:32:default"}[job["architecture"]]
    if parameters.get("language_id") != language:
        raise ToolFailure(f"{tool} analysis profile uses another processor language")
    for key in ["architecture", "entry_point"]:
        if parameters.get(key) != job[key]:
            raise ToolFailure(f"{tool} analysis profile disagrees on {key}")
    if "load_address" in job and parameters.get("load_address") != job["load_address"]:
        raise ToolFailure(f"{tool} analysis profile disagrees on load_address")
    if "load_address" not in job and parameters.get("load_address", job["entry_point"]) != job["entry_point"]:
        raise ToolFailure(f"{tool} legacy analysis profile changed the load address")


class ReaConnection:
    def __init__(self, session, identity):
        self.session = session
        self.identity = identity

    async def call(self, tool, arguments):
        return decode_reply(await self.session.call_tool(tool, arguments))


@asynccontextmanager
async def rea_connection(config: dict, directory: Path):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    identity_path = directory / f"process-{uuid.uuid4().hex}.json"
    command = config["rea"]
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(__file__).with_name("worker_launcher.py")), str(identity_path),
              command["command"], *command.get("args", [])],
        env=command.get("env"),
        cwd=command.get("cwd"),
    )
    with (directory / "stderr.log").open("a", encoding="utf-8") as stderr:
        async with stdio_client(params, errlog=stderr) as (read, write):
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), config["startup_timeout"])
                identity = json.loads(identity_path.read_text())
                yield ReaConnection(session, identity)


class Coordinator:
    """Run independent investigation jobs with a bounded persistent REA pool.

    The injectable connection factory supports lifecycle tests without installing
    Ghidra. Real-provider verification uses the same public workflow unchanged.
    """

    def __init__(self, config: dict, output: str | Path, *, connection_factory=rea_connection):
        self.config = validate_config(config)
        self.output = Path(output).expanduser().resolve()
        self.connection_factory = connection_factory
        self.run_dir: Path | None = None
        self.results: dict[str, dict] = {}
        self.active = 0
        self.peak_active = 0
        self.events: list[dict] = []
        self.running_jobs: set[str] = set()
        self.worker_errors: list[dict] = []

    def event(self, kind: str, **fields) -> None:
        event = {"event": kind, "at": utc_now(), "monotonic": time.monotonic(), **fields}
        self.events.append(event)
        with (self.run_dir / "events.jsonl").open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")

    async def _call(self, connection, report, directory, tool, arguments, *, cleanup=False):
        ordinal = len(report["calls"])
        relative = f"calls/{ordinal:03d}-{tool}.json"
        call = {"tool": tool, "arguments": arguments, "path": relative,
                "started_at": utc_now(), "started_monotonic": time.monotonic()}
        report["calls"].append(call)
        try:
            timeout = self.config["cleanup_timeout" if cleanup else "call_timeout"]
            reply = await asyncio.wait_for(connection.call(tool, arguments), timeout)
            call["reply"] = reply
            if reply["is_error"]:
                raise ToolFailure(f"{tool} returned an MCP tool error")
            structured = reply["structured"]
            if isinstance(structured, dict):
                if structured.get("ok") is False or ("error" in structured and "evidence_id" not in structured):
                    raise ToolFailure(f"{tool} returned a structured failure")
                if tool not in {"close_binary", "export_evidence_bundle"}:
                    verify_reply_binding(tool, structured, report)
                evidence_id = structured.get("evidence_id")
                if evidence_id:
                    call["evidence_id"] = evidence_id
                report["limitations"].extend(str(x) for x in structured.get("limitations", []))
            return structured
        except BaseException as exc:
            call["error"] = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            call["finished_at"] = utc_now()
            call["finished_monotonic"] = time.monotonic()
            atomic_json(directory / relative, call)

    async def _investigate(self, worker, connection, job):
        directory = self.run_dir / "jobs" / job["id"]
        directory.mkdir(parents=True)
        (directory / "calls").mkdir()
        report = {"id": job["id"], "worker": worker, "input": job,
                  "worker_identity": connection.identity, "status": "running", "calls": [],
                  "limitations": [], "questions": [{"question": q, "status": "unresolved"} for q in job["questions"]],
                  "started_at": utc_now(), "started_monotonic": time.monotonic()}
        cancelled = False
        opened = False
        self.active += 1
        self.running_jobs.add(job["id"])
        self.peak_active = max(self.peak_active, self.active)
        self.event("job_started", job=job["id"], worker=worker)
        try:
            path = Path(job["path"])
            before = await asyncio.to_thread(file_hash, path)
            report["source_sha256_before"] = before
            report["selected_source_matches"] = before == job["sha256"]
            if before != job["sha256"]:
                raise ValueError("Source SHA-256 differs from the selected image")
            size = path.stat().st_size
            base, entry = int(job.get("load_address", job["entry_point"]), 16), int(job["entry_point"], 16)
            if not size or base + size > 2**32 or not base <= entry < base + size:
                raise ValueError("Load range or execution entry is outside the image address space")
            opened = True  # Even a failed open may own resources requiring close.
            open_arguments = {
                "path": job["path"], "format": "raw-binary", "architecture": job["architecture"],
                "entry_point": job["entry_point"], "provider_id": "ghidra",
            }
            if "load_address" in job:
                open_arguments["load_address"] = job["load_address"]
            await self._call(connection, report, directory, "open_binary", open_arguments)
            report["opened_monotonic"] = time.monotonic()
            await self._call(connection, report, directory, "binary_session", {"detail": "complete"})
            await self._call(connection, report, directory, "binary_overview", {})
            for operation in job["operations"]:
                await self._call(connection, report, directory, operation["tool"], operation.get("arguments", {}))
            report["status"] = "completed"
        except asyncio.CancelledError:
            cancelled = True
            report["status"] = "cancelled"
        except Exception as exc:
            report["status"] = "failed"
            report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        finally:
            if opened:
                for tool, arguments, field in [
                    ("export_evidence_bundle", {"path": str(directory / "evidence.json")}, "evidence_exported"),
                    ("close_binary", {}, "closed"),
                ]:
                    try:
                        await self._call(connection, report, directory, tool, arguments, cleanup=True)
                        report[field] = True
                    except Exception as exc:
                        report[field] = False
                        report.setdefault("cleanup_errors", []).append({"tool": tool, "type": type(exc).__name__, "message": str(exc)})
                        if report["status"] == "completed":
                            report["status"] = "failed"
                report["closed_monotonic"] = time.monotonic()
            try:
                report["source_sha256_after"] = await asyncio.to_thread(file_hash, Path(job["path"]))
                report["source_unchanged"] = report["source_sha256_after"] == report.get("source_sha256_before")
            except OSError as exc:
                report["source_unchanged"] = False
                report["source_verification_error"] = str(exc)
            if not report["source_unchanged"] and report["status"] == "completed":
                report["status"] = "failed"
            report["limitations"] = list(dict.fromkeys(report["limitations"]))
            report["finished_at"] = utc_now()
            report["finished_monotonic"] = time.monotonic()
            self.active -= 1
            self.running_jobs.discard(job["id"])
            self.results[job["id"]] = report
            atomic_json(directory / "job.json", report)
            self.event("job_finished", job=job["id"], worker=worker, status=report["status"])
            if report["status"] == "completed":
                with (self.run_dir / "findings.jsonl").open("a", encoding="utf-8", newline="\n") as stream:
                    stream.write(json.dumps({"job": job["id"], "authority": "static-tool-observation",
                        "finding": "Requested static observations are retained in the Evidence bundle; behavior remains unverified.",
                        "evidence_path": f"jobs/{job['id']}/evidence.json",
                        "evidence_ids": [c["evidence_id"] for c in report["calls"] if "evidence_id" in c]}) + "\n")
            with (self.run_dir / "unknowns.jsonl").open("a", encoding="utf-8", newline="\n") as stream:
                for question in report["questions"]:
                    stream.write(json.dumps({"job": job["id"], **question}) + "\n")
        if cancelled:
            raise asyncio.CancelledError
        return report

    async def _retire_worker(self, stack, number):
        try:
            await stack.aclose()
            return True
        except Exception as exc:
            error = {"worker": number, "type": type(exc).__name__, "message": str(exc)}
            self.worker_errors.append(error)
            self.event("worker_cleanup_failed", **error)
            return False

    async def _worker(self, number, queue):
        directory = self.run_dir / "workers" / str(number)
        directory.mkdir(parents=True)
        stack = AsyncExitStack()
        connection = None
        try:
            while True:
                try:
                    job = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                try:
                    if connection is None:
                        connection = await stack.enter_async_context(self.connection_factory(self.config, directory))
                    result = await self._investigate(number, connection, job)
                    if result.get("closed") is False:
                        if not await self._retire_worker(stack, number):
                            break
                        stack = AsyncExitStack()
                        connection = None
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    # Startup/transport failure belongs to this job. Later jobs
                    # get a fresh owned process instead of inheriting its state.
                    self.results.setdefault(job["id"], {"id": job["id"], "worker": number, "status": "failed",
                        "input": job, "error": {"type": type(exc).__name__, "message": str(exc)}})
                    try:
                        if not await self._retire_worker(stack, number):
                            break
                    finally:
                        stack = AsyncExitStack()
                        connection = None
                finally:
                    queue.task_done()
        finally:
            await self._retire_worker(stack, number)

    async def run(self) -> dict:
        self.output.mkdir(parents=True, exist_ok=True)
        self.run_dir = self.output / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:12])
        self.run_dir.mkdir()
        for name in ["events.jsonl", "findings.jsonl", "unknowns.jsonl"]:
            (self.run_dir / name).touch()
        # Explicit configuration is caller data. Persist only the job plan and
        # executable coordinates; configured environment values are not exported.
        atomic_json(self.run_dir / "plan.json", {"schema_version": 1, "workers": self.config["workers"], "jobs": self.config["jobs"],
            "rea": {key: self.config["rea"][key] for key in ["command", "args", "cwd"] if key in self.config["rea"]}})
        queue = asyncio.Queue()
        for job in self.config["jobs"]:
            queue.put_nowait(job)
        started = time.monotonic()
        self.event("run_started")
        tasks = [asyncio.create_task(self._worker(i, queue), name=f"rea-worker-{i}")
                 for i in range(min(self.config["workers"], len(self.config["jobs"])))]
        cancelled = False
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            cancelled = True
            for task in tasks:
                if not task.cancelling():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for job in self.config["jobs"]:
                self.results.setdefault(job["id"], {"id": job["id"], "input": job,
                    "status": "cancelled" if cancelled else "failed", "error": {"type": "NotRun", "message": "Worker did not produce a result"}})
            jobs = [self.results[job["id"]] for job in self.config["jobs"]]
            report = {"schema_version": 1, "run_directory": str(self.run_dir), "status": "cancelled" if cancelled else
                      "completed" if all(j["status"] == "completed" for j in jobs) and not self.worker_errors else "failed",
                      "workers": self.config["workers"], "peak_active_jobs": self.peak_active,
                      "elapsed_seconds": time.monotonic() - started, "jobs": jobs, "worker_errors": self.worker_errors,
                      "limitations": ["Static analysis is not runtime or behavioral equivalence proof.",
                                       "Questions remain unresolved until an analyst or explicit verifier cites supporting observations.",
                                       "No cross-run result cache is used; every requested investigation is fresh."]}
            atomic_json(self.run_dir / "report.json", report)
            self.event("run_finished", status=report["status"])
        if cancelled:
            raise asyncio.CancelledError
        return report
