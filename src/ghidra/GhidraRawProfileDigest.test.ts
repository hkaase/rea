import { describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { silentLogger } from "../logger.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";
import { GhidraProvider } from "./GhidraProvider.js";

// Digests commit to the current shared policy, including the instruction status
// revision that prevents reuse of snapshots with the previous ambiguous result.
const RAW_DIGESTS = {
  "6502": "8e33776d1cc5c5d77d32923d5978c05ec2d989d00920dd458cc2dafb4c9c0cad",
  "x86-disabled-analyzer":
    "d17bddc8ac110c891d30fb989fc7906df421bd9bea5df4aac05a950f50c7bdaf",
} as const;

const configFor = (environment: NodeJS.ProcessEnv) => {
  const parsed = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra", ...environment });
  if (!parsed.ok) throw parsed.error;
  return parsed.value;
};

const raw = (architecture: "6502" | "x86", entryPoint: string): BinaryTarget =>
  ({
    path: "/tmp/raw.bin",
    sha256: "a".repeat(64),
    kind: "executable",
    format: "raw-binary",
    architecture,
    availableArchitectures: [architecture],
    entryPoint,
    entryPointSource: entryPoint,
  }) as unknown as BinaryTarget;

describe("raw-binary analysis profile digest", () => {
  it("commits the 6502 raw profile to the current shared policy", async () => {
    const ghidra = new GhidraProvider(configFor({}), silentLogger, {}, host);
    const resolved = await ghidra.resolveAnalysisProfile(raw("6502", "0x8001"));
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value.profile?.digest).toBe(RAW_DIGESTS["6502"]);
    expect(resolved.value.profile?.parameters).toMatchObject({
      target_format: "raw-binary",
      loader: "BinaryLoader",
      language_id: "6502:LE:16:default",
      language_selection: "caller-supplied-v1",
      load_image_evidence: "independent-raw-mapping-context-v4",
      instruction_status: "unlisted-address-without-decode-v1",
      analyzer_preset: "ghidra-default",
    });
  });

  it("keeps the disabled-analyzer raw digest and its analysis options", async () => {
    const ghidra = new GhidraProvider(
      configFor({
        REA_GHIDRA_DISABLED_ANALYZERS: "Aggressive Instruction Finder",
      }),
      silentLogger,
      {},
      host,
    );
    const resolved = await ghidra.resolveAnalysisProfile(raw("x86", "0x1000"));
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value.profile?.digest).toBe(
      RAW_DIGESTS["x86-disabled-analyzer"],
    );
    expect(resolved.value.profile?.parameters).toMatchObject({
      analysis_options: {
        disabled_analyzers: ["Aggressive Instruction Finder"],
      },
    });
  });
});

describe("raw firmware profile commitments", () => {
  it("changes identity when load address changes independently of entry", async () => {
    const target: Extract<BinaryTarget, { format: "raw-binary" }> = {
      path: "/tmp/pcm.bin",
      sha256: "a".repeat(64),
      kind: "executable",
      format: "raw-binary",
      architecture: "cpu32",
      availableArchitectures: ["cpu32"],
      entryPoint: "0x440",
      entryPointSource: "0x440",
      loadAddress: "0x0",
    };
    const provider = new GhidraProvider(configFor({}), silentLogger, {}, host);
    const first = await provider.resolveAnalysisProfile(target);
    const second = await provider.resolveAnalysisProfile({
      ...target,
      loadAddress: "0x100",
    });
    if (!first.ok || !second.ok) throw new Error("expected firmware profiles");
    expect(first.value.profile?.parameters).toMatchObject({
      load_address: "0x0",
      entry_point: "0x440",
      language_id: "68000:BE:32:CPU32",
    });
    expect(second.value.profile?.digest).not.toBe(first.value.profile?.digest);
  });
  it("admits a raw PowerPC profile without inventing ELF metadata", async () => {
    const target: BinaryTarget = {
      path: "/tmp/ppc.bin",
      sha256: "a".repeat(64),
      kind: "executable",
      format: "raw-binary",
      architecture: "powerpc",
      availableArchitectures: ["powerpc"],
      entryPoint: "0x100",
      entryPointSource: "0x100",
      loadAddress: "0x0",
    };
    const provider = new GhidraProvider(configFor({}), silentLogger, {}, host);
    const result = await provider.resolveAnalysisProfile(target);
    if (!result.ok) throw result.error;
    expect(result.value.profile?.parameters).toMatchObject({
      load_address: "0x0",
      entry_point: "0x100",
      language_id: "PowerPC:BE:32:default",
    });
  });
});
