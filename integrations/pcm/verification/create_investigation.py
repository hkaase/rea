"""Create the exact four-job REA verification plan from local research inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[1]


def instruction(address: str) -> dict:
    return {"tool": "inspect_native_instruction", "arguments": {"address": address}}


def procedure(tool: str, address: str, *, detail: bool = False) -> dict:
    args = {"procedure": address}
    if detail:
        args["detail"] = "complete"
    return {"tool": tool, "arguments": args}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis-root", type=Path, default=Path("/opt/pcm-reversal"))
    parser.add_argument("--output", type=Path, default=WORKSPACE / ".analysis/parallel-investigation.json")
    parser.add_argument("--workers", type=int, choices=range(1, 5), default=2)
    parser.add_argument("--rea-root", type=Path)
    parser.add_argument("--node", type=Path)
    parser.add_argument("--ghidra", type=Path)
    args = parser.parse_args()
    analysis = args.analysis_root.resolve()
    fixtures = json.loads((analysis / "verification-fixtures/manifest.json").read_text())["fixtures"]
    specifications = [
        {
            "id": "p59-startup", "profile": "p59_12587603", "architecture": "cpu32", "entry": "0x440",
            "questions": ["What instructions and direct calls are statically visible after the P59 reset-vector entry?", "Which early register writes are visible, and which peripheral meanings remain unknown?"],
            "operations": [{"tool": "read_bytes", "arguments": {"address": "0x4", "length": 4}}, instruction("0x440"), instruction("0x44a"), procedure("read_function_instructions", "0x440"), procedure("analyze_function", "0x440", detail=True), procedure("procedure_references", "0x440")],
        },
        {
            "id": "e38-startup", "profile": "e38_12607218", "architecture": "powerpc", "entry": "0x100",
            "questions": ["Where does the observed E38 branch stub at 0x100 transfer control?", "What initialization instructions are statically visible in its target at 0x168?"],
            "operations": [instruction("0x100"), instruction("0x168"), instruction("0x170"), instruction("0x174"), instruction("0x178"), procedure("read_function_instructions", "0x168"), procedure("analyze_function", "0x168", detail=True), procedure("procedure_references", "0x100")],
        },
        {
            "id": "cpu32-table-fixture", "fixture": "cpu32", "architecture": "cpu32", "entry": "0x20",
            "questions": ["Does the CPU32 language decode the GNU-assembled TBLU instruction at 0x24 and produce pseudocode for the table interpolation function?"],
            "operations": [instruction("0x24"), procedure("read_function_instructions", "0x20"), procedure("analyze_function", "0x20", detail=True)],
        },
        {
            "id": "powerpc-call-fixture", "fixture": "powerpc", "architecture": "powerpc", "entry": "0x0",
            "questions": ["Does the PowerPC language decode the branch-and-link at 0x8 to the helper at 0x20?", "Does helper pseudocode retain the source-owned constant return value 7?"],
            "operations": [instruction("0x8"), instruction("0x20"), procedure("read_function_instructions", "0x0"), procedure("analyze_function", "0x20", detail=True), procedure("procedure_references", "0x0")],
        },
        {
            "id": "cpu32-relocated-fixture", "fixture": "cpu32", "architecture": "cpu32", "load": "0x1000", "entry": "0x1020",
            "questions": ["Are the unchanged raw bytes mapped at 0x1000 while the table function entry remains independently located at 0x1020?"],
            "operations": [instruction("0x1024"), procedure("read_function_instructions", "0x1020"), procedure("analyze_function", "0x1020", detail=True)],
        },
        {
            "id": "powerpc-relocated-fixture", "fixture": "powerpc", "architecture": "powerpc", "load": "0x2000", "entry": "0x2000",
            "questions": ["Does the same PowerPC call encoding at relocated address 0x2008 resolve to 0x2020 without changing source bytes?"],
            "operations": [instruction("0x2008"), procedure("read_function_instructions", "0x2000"), procedure("analyze_function", "0x2020", detail=True)],
        },
        {
            "id": "cpu32-legacy-fixture", "fixture": "cpu32", "architecture": "cpu32", "legacy": True, "entry": "0x4000",
            "questions": ["Does omitting load_address preserve the legacy mapping of file offset zero at entry_point?"],
            "operations": [instruction("0x4000"), procedure("read_function_instructions", "0x4000"), procedure("analyze_function", "0x4010", detail=True)],
        },
    ]
    jobs = []
    for specification in specifications:
        if "profile" in specification:
            profile = json.loads((WORKSPACE / "profiles" / f"{specification['profile']}.json").read_text())
            binary = analysis / "corpus" / f"{specification['profile']}.bin"
            expected_digest = profile["sha256"]
        else:
            fixture = fixtures[specification["fixture"]]
            binary = Path(fixture["binary"])
            expected_digest = fixture["sha256"]
        if hashlib.sha256(binary.read_bytes()).hexdigest() != expected_digest:
            raise ValueError(f"Source hash mismatch: {binary}")
        job = {
            "id": specification["id"], "path": str(binary), "sha256": expected_digest,
            "architecture": specification["architecture"],
            "entry_point": specification["entry"], "questions": specification["questions"],
            "operations": [
                {"tool": "inspect_native_load_image", "arguments": {"detail": "complete"}},
                {"tool": "list_procedures", "arguments": {"detail": "summary"}},
                *specification["operations"],
            ],
        }
        if not specification.get("legacy", False):
            job["load_address"] = specification.get("load", "0x0")
        jobs.append(job)
    config = {
        "schema_version": 1, "workers": args.workers,
        "rea": {
            "command": str(args.node.resolve() if args.node else analysis / "node/bin/node"),
            "args": [str((args.rea_root.resolve() if args.rea_root else analysis / "tools/rea") / "scripts/rea.mjs"), "mcp"],
            "env": {"GHIDRA_INSTALL_DIR": str(args.ghidra.resolve() if args.ghidra else analysis / "tools/ghidra_12.1.4_PUBLIC"), "REA_MCP_TOOL_FAMILIES": "session,direct,enhanced", "REA_GHIDRA_STARTUP_TIMEOUT_MS": "180000"},
        },
        "jobs": jobs,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(config, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
