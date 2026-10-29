"""Agent-facing submit/status/evidence API over the same coordinator lifecycle.

Usage: python -m coordinator.mcp_server --max-workers 4
The REA process budget is shared across all investigations in this server.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import uuid

from .runner import Coordinator, load_config, rea_connection


class InvestigationController:
    def __init__(self, max_workers=4, *, connection_factory=rea_connection):
        if max_workers < 1:
            raise ValueError("max_workers must be positive")
        self.semaphore = asyncio.Semaphore(max_workers)
        self.connection_factory = connection_factory
        self.runs = {}
        self.closing = False

    @asynccontextmanager
    async def connection(self, config, directory):
        async with self.semaphore:
            async with self.connection_factory(config, directory) as peer:
                yield peer

    def submit(self, config_path: str, output_directory: str) -> dict:
        if self.closing:
            raise RuntimeError("Coordinator is shutting down")
        config = load_config(config_path)
        coordinator = Coordinator(config, output_directory, connection_factory=self.connection)
        run_id = uuid.uuid4().hex
        record = {"id": run_id, "coordinator": coordinator, "state": "queued"}

        async def run():
            record["state"] = "running"
            try:
                report = await coordinator.run()
                record["state"] = report["status"]
            except asyncio.CancelledError:
                record["state"] = "cancelled"
            except Exception as exc:
                record["state"] = "failed"
                record["error"] = {"type": type(exc).__name__, "message": str(exc)}

        record["task"] = asyncio.create_task(run(), name=f"pcm-investigation-{run_id}")
        self.runs[run_id] = record
        return self.status(run_id)

    def _record(self, run_id):
        if run_id not in self.runs:
            raise ValueError("Unknown investigation id in this coordinator session")
        return self.runs[run_id]

    def status(self, run_id) -> dict:
        record = self._record(run_id)
        coordinator = record["coordinator"]
        return {"run_id": run_id, "state": record["state"], "active_jobs": coordinator.active,
            "peak_active_jobs": coordinator.peak_active,
            "run_directory": str(coordinator.run_dir) if coordinator.run_dir else None,
            "jobs": [{"id": job["id"], "status": coordinator.results.get(job["id"], {}).get("status",
                     "running" if job["id"] in coordinator.running_jobs else "pending")}
                     for job in coordinator.config["jobs"]],
            **({"error": record["error"]} if "error" in record else {})}

    async def cancel(self, run_id) -> dict:
        record = self._record(run_id)
        if not record["task"].done():
            record["task"].cancel()
            try:
                await asyncio.shield(record["task"])
            except asyncio.CancelledError:
                if not record["task"].cancelled():
                    raise
            # A task cancelled before its coroutine began never executes its
            # own state transition or acquires worker resources.
            if record["state"] == "queued":
                record["state"] = "cancelled"
        return self.status(run_id)

    def _job_directory(self, run_id, job_id) -> Path:
        coordinator = self._record(run_id)["coordinator"]
        if job_id not in {job["id"] for job in coordinator.config["jobs"]}:
            raise ValueError("Unknown job id in this investigation")
        if coordinator.run_dir is None:
            raise ValueError("Investigation has not started")
        return coordinator.run_dir / "jobs" / job_id

    def read_job(self, run_id, job_id):
        path = self._job_directory(run_id, job_id) / "job.json"
        if not path.is_file():
            return {"status": "pending", "job_id": job_id}
        job = json.loads(path.read_text())
        job["calls"] = [{key: value for key, value in call.items() if key != "reply"} for call in job.get("calls", [])]
        return job

    def read_call(self, run_id, job_id, call_index):
        if isinstance(call_index, bool) or not isinstance(call_index, int) or call_index < 0:
            raise ValueError("call_index must be nonnegative")
        directory = self._job_directory(run_id, job_id)
        matches = list((directory / "calls").glob(f"{call_index:03d}-*.json"))
        if len(matches) != 1:
            raise ValueError("No completed call has this index")
        return json.loads(matches[0].read_text())

    def read_evidence(self, run_id, job_id, evidence_id=None, offset=0, limit=32):
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be nonnegative")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be positive")
        path = self._job_directory(run_id, job_id) / "evidence.json"
        if not path.is_file():
            return {"status": "pending", "job_id": job_id}
        bundle = json.loads(path.read_text())
        records = bundle.get("records", [])
        if evidence_id is not None:
            matches = [record for record in records if record.get("evidence_id") == evidence_id]
            if len(matches) != 1:
                raise ValueError("Evidence id is absent or ambiguous in this job's bundle")
            return matches[0]
        page = [{"evidence_id": record.get("evidence_id"), "operation": record.get("operation"),
                 "confidence": record.get("confidence"), "authority": record.get("authority"),
                 "limitations": record.get("limitations", [])}
                for record in records[offset:offset + limit]]
        return {"status": "available", "path": str(path), "total": len(records), "offset": offset,
                "next_offset": offset + len(page) if offset + len(page) < len(records) else None,
                "records": page}

    async def close(self):
        self.closing = True
        records = list(self.runs.values())
        for record in records:
            if not record["task"].done() and not record["task"].cancelling():
                record["task"].cancel()
        await asyncio.gather(*(record["task"] for record in records), return_exceptions=True)
        for record in records:
            if record["task"].cancelled():
                record["state"] = "cancelled"


def create_server(max_workers=4):
    from mcp.server.fastmcp import FastMCP

    controller = InvestigationController(max_workers)

    @asynccontextmanager
    async def lifespan(server):
        try:
            yield controller
        finally:
            await controller.close()

    server = FastMCP("pcm-investigation-coordinator", lifespan=lifespan,
        instructions="Submit an explicit static investigation plan, poll status, then read selected job calls or evidence. "
        "Workers own independent REA/Ghidra sessions. Evidence supports static observations; do not infer runtime correctness.")

    @server.tool()
    async def submit_investigation(config_path: str, output_directory: str) -> dict:
        """Queue a local JSON investigation plan and return its run id immediately."""
        return controller.submit(config_path, output_directory)

    @server.tool()
    async def investigation_status(run_id: str) -> dict:
        """Read current job completion and owned run-directory coordinates."""
        return controller.status(run_id)

    @server.tool()
    async def cancel_investigation(run_id: str) -> dict:
        """Cancel an investigation, export available evidence, and close its workers."""
        return await controller.cancel(run_id)

    @server.tool()
    async def read_investigation_job(run_id: str, job_id: str) -> dict:
        """Read a completed job's provenance, calls, limitations, and unresolved questions."""
        return controller.read_job(run_id, job_id)

    @server.tool()
    async def read_investigation_call(run_id: str, job_id: str, call_index: int) -> dict:
        """Read one completed call with its full structured REA response and timing."""
        return controller.read_call(run_id, job_id, call_index)

    @server.tool()
    async def read_investigation_evidence(run_id: str, job_id: str, evidence_id: str | None = None,
                                          offset: int = 0, limit: int = 32) -> dict:
        """Page Evidence metadata, or retrieve one exact retained Evidence id."""
        return controller.read_evidence(run_id, job_id, evidence_id, offset, limit)

    return server


def main():
    parser = argparse.ArgumentParser(description="Parallel PCM investigation MCP server")
    parser.add_argument("--max-workers", type=int, default=4)
    args = parser.parse_args()
    create_server(args.max_workers).run(transport="stdio")


if __name__ == "__main__":
    main()
