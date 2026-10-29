"""Independently check exported REA evidence against source bytes and job inputs.

This checker validates the specified static observations. It does not establish
runtime behavior, complete function discovery, or decompiler semantic equivalence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

LANGUAGES = {"cpu32": "68000:BE:32:CPU32", "powerpc": "PowerPC:BE:32:default"}


def number(value: str | int) -> int:
    return value if isinstance(value, int) else int(value, 16)


def checked(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def by_operation(records: list[dict], operation: str) -> list[dict]:
    return [record for record in records if record["operation"] == operation]


def engine_profile(record: dict, records: dict[str, dict], seen: frozenset[str] = frozenset()) -> dict:
    identifier = record["evidence_id"]
    checked(identifier not in seen, "Evidence projection links contain a cycle")
    provider = record["provider"]["id"]
    profile = record["analysis_profile"]
    if provider == "rea-analysis-view":
        checked(profile is None, "Analysis view unexpectedly claims a native analysis profile")
        view = record["normalized_result"]
        parent_id = view["parent_evidence_id"]
        checked(parent_id in records and parent_id in record["evidence_links"], "Analysis projection lost its retained parent")
        parent = records[parent_id]
        checked(view["source_provider"] == parent["provider"], "Projection source provider differs from retained parent")
        checked(view["source_analysis_profile_digest"] == parent["analysis_profile"]["digest"], "Projection source profile differs from retained parent")
        return engine_profile(parent, records, seen | {identifier})
    checked(profile["provider"]["id"] == provider, "Evidence and profile provider identities disagree")
    if provider == "rea-workflow":
        profile = profile["parameters"]["upstream_analysis_profile"]
    else:
        checked(provider == "ghidra", "Evidence came from an unexpected producer")
    checked(profile["provider"]["id"] == "ghidra", "Evidence is not bound to the Ghidra engine")
    return profile


def check_bundle(bundle_path: Path, job: dict) -> dict:
    source = Path(job["path"]).read_bytes()
    checked(hashlib.sha256(source).hexdigest() == job["sha256"], "Source bytes changed")
    bundle = json.loads(bundle_path.read_text())
    records = bundle["records"]
    record_by_id = {record["evidence_id"]: record for record in records}
    checked(bool(records), "Evidence bundle is empty")
    checked(len({record["evidence_id"] for record in records}) == len(records), "Duplicate Evidence IDs")
    for record in records:
        checked(record["subject"]["digest"]["sha256"] == job["sha256"], "Evidence has the wrong source identity")
        profile = engine_profile(record, record_by_id)
        checked(profile["parameters"]["architecture"] == job["architecture"], "Engine profile architecture differs")
    load_records = by_operation(records, "inspect_native_load_image")
    checked(len(load_records) == 1, "Expected exactly one complete load-image record")
    load_evidence = load_records[0]
    load = load_evidence["normalized_result"]
    base = number(job.get("load_address", job["entry_point"]))
    entry = number(job["entry_point"])
    checked(load["status"] == "verified", "Independent load-image attestation did not verify")
    checked(load["architecture"] == job["architecture"], "Architecture differs")
    checked(load["language_id"] == LANGUAGES[job["architecture"]], "Ghidra language differs")
    checked(number(load["base_address"]) == base, "Raw file was mapped at the wrong base")
    checked(number(load["entry"]["address"]) == entry, "Execution entry differs")
    checked(load["entry"]["file_offset"] == entry - base, "Entry file offset differs")
    checked(load["target_sha256"] == job["sha256"], "Load image source identity differs")
    checked(load["file_bytes"] == len(source), "Load image file extent differs")
    checked(all(item["matched"] for item in load["checks"]), "At least one independent mapping check mismatched")
    measured_source = load["observations"]["source_files"][0]
    checked(measured_source["original_sha256"] == job["sha256"], "Ghidra's original bytes differ")
    checked(measured_source["modified_sha256"] == job["sha256"], "Ghidra modified executable bytes")
    file_maps = [item for item in load["observations"]["mappings"] if item["source_file_index"] is not None]
    checked(len(file_maps) == 1, "Expected one linear source-backed mapping")
    checked(number(file_maps[0]["start"]) == base and number(file_maps[0]["end"]) == base + len(source) - 1, "Mapped byte range differs")
    profile = load_evidence["analysis_profile"]
    checked(profile["parameters"]["language_id"] == LANGUAGES[job["architecture"]], "Profile language differs")
    checked(number(profile["parameters"]["entry_point"]) == entry, "Profile entry differs")
    checked(number(profile["parameters"].get("load_address", job["entry_point"])) == base, "Profile load address differs")
    instruction_records = by_operation(records, "inspect_native_instruction")
    instructions = {}
    instruction_evidence = {}
    for record in instruction_records:
        instruction = record["normalized_result"]
        address = number(instruction["address"])
        checked(instruction["status"] == "decoded", f"Instruction at {address:#x} was not decoded")
        checked(instruction["length"] > 0, "Instruction length is missing")
        raw = re.sub(r"\s", "", instruction["bytes"] or "").lower()
        start = address - base
        checked(source[start:start + instruction["length"]].hex() == raw, f"Instruction bytes at {address:#x} disagree with original file")
        instructions[address] = instruction
        instruction_evidence[address] = record["evidence_id"]
    checked(bool(instructions), "No exact instruction observations were retained")
    identifier = job["id"]
    if identifier in {"cpu32-table-fixture", "cpu32-relocated-fixture"}:
        table = instructions[base + 0x24]
        checked(table["mnemonic"].lower().startswith("tblu"), "CPU32 TBLU decoded as another instruction")
        checked(re.sub(r"\s", "", table["bytes"]).lower() == "f8100100", "CPU32 table encoding differs from GNU assembler")
    if identifier in {"powerpc-call-fixture", "powerpc-relocated-fixture"}:
        call = instructions[base + 8]
        checked(call["flow"]["kind"] == "call", "PowerPC branch-and-link was not classified as a call")
        checked(base + 0x20 in [number(value) for value in call["flow"]["direct_destinations"]], "PowerPC call destination differs from linked source")
    if identifier == "e38-startup":
        branch = instructions[0x100]
        checked(branch["flow"]["kind"] == "jump", "E38 branch stub was not classified as a jump")
        checked(0x168 in [number(value) for value in branch["flow"]["direct_destinations"]], "E38 branch destination differs from encoded offset")
    if identifier == "p59-startup":
        checked(int.from_bytes(source[4:8], "big") == entry, "P59 reset vector does not point to the selected entry")
        first = instructions[0x440]
        checked(first["mnemonic"].lower().startswith("suba"), "P59 vector entry begins with an unexpected instruction")
    dossiers = by_operation(records, "analyze_function")
    checked(bool(dossiers), "No complete function dossier was retained")
    for dossier in dossiers:
        result = dossier["normalized_result"]
        checked(bool(result["pseudocode"].strip()), "Function pseudocode is empty")
        checked(bool(result["assembly"]), "Function assembly is empty")
    if "fixture" in identifier:
        checked(all("unimplemented" not in record["normalized_result"]["pseudocode"].lower() for record in dossiers), "Fixture decompilation contains an unimplemented operation")
    if identifier in {"powerpc-call-fixture", "powerpc-relocated-fixture", "cpu32-legacy-fixture"}:
        checked(any(re.search(r"return\s+(?:0x)?7\s*;", record["normalized_result"]["pseudocode"]) for record in dossiers), "Source-owned helper return constant was lost")
    warnings = []
    for dossier in dossiers:
        result = dossier["normalized_result"]
        warnings.extend(result.get("limitations", []))
        warnings.extend(line.strip() for line in result["pseudocode"].splitlines() if "WARNING:" in line)
    inventories = by_operation(records, "list_procedures")
    inventory_count = len(inventories[0]["normalized_result"]) if inventories and isinstance(inventories[0]["normalized_result"], list) else None
    findings = [{"confidence": "observed", "finding": f"The source image maps at {base:#x}, with selected execution entry {entry:#x} at file offset {entry-base:#x}, under {load['language_id']}.", "evidence_ids": [load_evidence["evidence_id"]]}]
    if identifier == "p59-startup":
        vector_records = by_operation(records, "read_bytes")
        checked(len(vector_records) == 1, "P59 vector bytes were not retained")
        vector = vector_records[0]["normalized_result"]
        checked(number(vector["address"]) == 4 and vector["complete"] and vector["bytes_hex"] == source[4:8].hex(), "Observed P59 vector bytes differ from original source")
        findings.append({"confidence": "observed", "finding": "The big-endian source reset vector at file offset 4 selects 0x440; the first decoded instruction there clears A6 with SUBA.", "evidence_ids": [record["evidence_id"] for record in vector_records] + [instruction_evidence[0x440], load_evidence["evidence_id"]]})
        findings.append({"confidence": "observed", "finding": f"Early startup contains the decoded instruction {instructions[0x44a]['raw_disassembly']} at 0x44a. Its peripheral meaning remains unverified.", "evidence_ids": [instruction_evidence[0x44a], dossiers[0]["evidence_id"]]})
    elif identifier == "e38-startup":
        findings.append({"confidence": "observed", "finding": "The branch instruction at 0x100 has an encoded direct target of 0x168.", "evidence_ids": [instruction_evidence[0x100]]})
        findings.append({"confidence": "observed", "finding": "The early initialization sequence at 0x170, 0x174 and 0x178 decodes as: " + "; ".join(instructions[address]["raw_disassembly"] for address in [0x170, 0x174, 0x178]) + ". These are static instruction observations; hardware register meanings remain unknown.", "evidence_ids": [instruction_evidence[address] for address in [0x170, 0x174, 0x178]] + [dossiers[0]["evidence_id"]]})
    elif identifier in {"cpu32-table-fixture", "cpu32-relocated-fixture"}:
        findings.append({"confidence": "observed", "finding": f"GNU-assembled bytes f8100100 at {base+0x24:#x} decode as {instructions[base+0x24]['raw_disassembly']} and the table function produces nonempty pseudocode without unimplemented-operation markers.", "evidence_ids": [instruction_evidence[base+0x24], dossiers[0]["evidence_id"]]})
    elif identifier in {"powerpc-call-fixture", "powerpc-relocated-fixture"}:
        findings.append({"confidence": "observed", "finding": f"The branch-and-link instruction at {base+8:#x} resolves to {base+0x20:#x}; the source-owned helper decompiles with return constant 7.", "evidence_ids": [instruction_evidence[base+8], dossiers[0]["evidence_id"]]})
    elif identifier == "cpu32-legacy-fixture":
        findings.append({"confidence": "observed", "finding": "Omitting load_address preserves legacy mapping at entry_point 0x4000; the relative call reaches the helper whose return value is 7.", "evidence_ids": [load_evidence["evidence_id"], instruction_evidence[0x4000], dossiers[0]["evidence_id"]]})
    return {
        "job_id": identifier, "status": "passed", "bundle": str(bundle_path),
        "evidence_records": len(records), "load_address": hex(base), "entry_point": hex(entry),
        "language": load["language_id"], "source_sha256": job["sha256"],
        "profile_digest": profile["digest"], "instruction_addresses": [hex(value) for value in sorted(instructions)],
        "dossier_count": len(dossiers), "warnings": warnings,
        "provider_reported_procedure_count": inventory_count,
        "procedure_discovery_coverage": "unknown",
        "findings": findings,
        "limitations": ["Static analysis only; no firmware execution.", "Instruction and byte agreement do not prove complete processor or peripheral semantics.", "Pseudocode presence does not establish semantic equivalence."],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--job", required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    job = next(job for job in config["jobs"] if job["id"] == args.job)
    print(json.dumps(check_bundle(args.bundle, job), indent=2))


if __name__ == "__main__":
    main()
