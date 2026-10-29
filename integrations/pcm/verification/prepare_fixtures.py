"""Build source-owned raw fixtures with GNU assemblers, without executing them."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[1]
EXPECTED = {
    "cpu32": "3352b2aacc8879da6492563269c83a34dee4e0d5270d2d76cb9d7805f1fe02dd",
    "powerpc": "0066a816e47e08e5d211b463944af39dbdc4f82eaff179f8e700004868795f15",
}


def run(command: list[str]) -> str:
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("/opt/pcm-reversal/verification-fixtures"))
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest = {"schema_version": 1, "fixtures": {}}
    for architecture, source, prefix, flags in [
        ("cpu32", WORKSPACE / "fixtures/cpu32.s", "m68k-linux-gnu", ["-mcpu=68332"]),
        ("powerpc", WORKSPACE / "verification/fixtures/powerpc.S", "powerpc-linux-gnu", ["-mppc"]),
    ]:
        obj = output / f"{architecture}.o"
        elf = output / f"{architecture}.elf"
        binary = output / f"{architecture}.bin"
        run([prefix + "-as", *flags, "-o", str(obj), str(source)])
        run([prefix + "-ld", "-Ttext=0", "--entry=probe_entry", "-o", str(elf), str(obj)])
        run([prefix + "-objcopy", "-O", "binary", str(elf), str(binary)])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if digest != EXPECTED[architecture]:
            raise ValueError(f"{architecture} fixture differs from the independently specified bytes: {digest}")
        assembly = run([prefix + "-objdump", "-d", str(elf)])
        (output / f"{architecture}.objdump.txt").write_text(assembly)
        manifest["fixtures"][architecture] = {
            "binary": str(binary), "sha256": digest, "bytes": binary.stat().st_size,
            "source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "assembler": run([prefix + "-as", "--version"]).splitlines()[0],
            "objdump": str(output / f"{architecture}.objdump.txt"),
        }
    destination = output / "manifest.json"
    destination.write_text(json.dumps(manifest, indent=2) + "\n")
    print(destination)


if __name__ == "__main__":
    main()
