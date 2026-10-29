"""Exercise the public coordinator MCP adapter with a real REA/Ghidra job."""

import asyncio
import json
from pathlib import Path
import sys
import time

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

WORKSPACE = Path(__file__).resolve().parents[1]


def result_value(result):
    if result.isError:
        raise RuntimeError(str(result.content))
    if result.structuredContent is not None:
        return result.structuredContent
    return json.loads("\n".join(block.text for block in result.content if block.type == "text"))


async def main():
    source_plan = json.loads((WORKSPACE / ".analysis/parallel-investigation.json").read_text())
    source_plan["jobs"] = [next(job for job in source_plan["jobs"] if job["id"] == "cpu32-table-fixture")]
    source_plan["workers"] = 1
    config_path = WORKSPACE / ".analysis/coordinator-mcp-plan.json"
    config_path.write_text(json.dumps(source_plan, indent=2) + "\n")
    params = StdioServerParameters(command=sys.executable,
        args=["-m", "coordinator.mcp_server", "--max-workers", "2"], cwd=str(WORKSPACE))
    started = time.monotonic()
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            available = [tool.name for tool in (await session.list_tools()).tools]

            async def call(name, arguments):
                return result_value(await session.call_tool(name, arguments))

            submitted = await call("submit_investigation", {
                "config_path": str(config_path),
                "output_directory": str(WORKSPACE / ".analysis/coordinator-mcp-run"),
            })
            run_id = submitted["run_id"]
            print(json.dumps({"event": "submitted", "run_id": run_id, "tools": available}), flush=True)
            while True:
                status = await call("investigation_status", {"run_id": run_id})
                if status["state"] in {"completed", "failed", "cancelled"}:
                    break
                if time.monotonic() - started > 240:
                    await call("cancel_investigation", {"run_id": run_id})
                    raise TimeoutError("Coordinator MCP investigation did not complete")
                await asyncio.sleep(0.5)
            assert status["state"] == "completed", status
            job = await call("read_investigation_job", {"run_id": run_id, "job_id": "cpu32-table-fixture"})
            assert all("reply" not in entry for entry in job["calls"]), "Job summary expanded full replies"
            page = await call("read_investigation_evidence", {
                "run_id": run_id, "job_id": "cpu32-table-fixture", "offset": 0, "limit": 2,
            })
            assert len(page["records"]) == 2 and page["next_offset"] == 2, page
            exact = await call("read_investigation_evidence", {
                "run_id": run_id, "job_id": "cpu32-table-fixture",
                "evidence_id": page["records"][0]["evidence_id"],
            })
            assert exact["evidence_id"] == page["records"][0]["evidence_id"]
            report = {"status": "passed", "tools": available, "run": status,
                "job_id": job["id"], "source_unchanged": job["source_unchanged"],
                "paged_records": page["total"], "exact_evidence_id": exact["evidence_id"],
                "elapsed_seconds": time.monotonic() - started}
    (WORKSPACE / ".analysis/coordinator-mcp-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
