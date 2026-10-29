import { describe, expect, it } from "vitest";

import { openBinaryInputSchema } from "./sessionLifecycleInputs.js";

describe("open_binary raw-binary input contract", () => {
  it("accepts header detection without architecture", () => {
    expect(
      openBinaryInputSchema.safeParse({ path: "/tmp/fixture.bin" }).success,
    ).toBe(true);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/legacy.com",
        format: "dos-com",
      }).success,
    ).toBe(true);
  });
  it("accepts raw-binary with architecture and entry", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
        entry_point: "0x8000000",
      }).success,
    ).toBe(true);
  });
  it("rejects raw-binary without architecture or entry", () => {
    const parsed = openBinaryInputSchema.safeParse({
      path: "/tmp/ecu.bin",
      format: "raw-binary",
    });
    expect(parsed.success).toBe(false);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
      }).success,
    ).toBe(false);
  });
  it("rejects architecture without format=raw-binary", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        architecture: "arm",
        entry_point: "0x8000000",
      }).success,
    ).toBe(false);
  });
});

describe("open_binary firmware load selection", () => {
  it.each(["cpu32", "powerpc"])(
    "accepts explicit %s firmware mapping",
    (architecture) => {
      expect(
        openBinaryInputSchema.parse({
          path: "/tmp/pcm.bin",
          format: "raw-binary",
          architecture,
          load_address: "0x0",
          entry_point: "0x100",
        }),
      ).toMatchObject({ load_address: "0x0", entry_point: "0x100" });
    },
  );
  it.each([undefined, "gamecube-dol", "dos-com"])(
    "rejects load selection for %s",
    (format) => {
      const input = {
        path: "/tmp/pcm.bin",
        load_address: "0x0",
        ...(format === undefined ? {} : { format }),
      };
      const parsed = openBinaryInputSchema.safeParse(input);
      expect(parsed.success).toBe(false);
      if (parsed.success) throw new Error("expected load selection refusal");
      expect(parsed.error.issues[0]?.path).toEqual(["load_address"]);
    },
  );
});
