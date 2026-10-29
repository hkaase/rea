# Verification receipt — October 29, 2026

The patched REA and coordinator completed a seven-job investigation with two workers, followed by the identical workload with one worker. All fourteen job runs passed independent checks, and REA's production bundle reader authenticated all fourteen exported evidence bundles. Original image hashes remained unchanged. The process-family observer found no surviving owned processes after either run.

| Configuration |  Elapsed | Sampled aggregate peak RSS | Sampled CPU lower bound |
| ------------- | -------: | -------------------------: | ----------------------: |
| Two workers   | 101.36 s |                   3.39 GiB |                665.01 s |
| One worker    | 178.03 s |                   2.39 GiB |                602.87 s |

The P59 and E38 analysis requests overlapped for 60.85 seconds. These are single measurements with fresh REA/Ghidra sessions and warm, uncontrolled operating-system caches. The parallel run preceded the serial run. RSS sampling can miss peaks and counts resident pages per process; CPU sampling can miss short-lived processes. This comparison establishes working parallel investigations on this workload and does not establish a general speedup.

## Evidence-backed findings

- P59 OS 12587603: the source reset vector at file offset 4 selects `0x440`. The image maps at zero under `68000:BE:32:CPU32`. Startup begins with `SUBA` clearing A6 and includes an early word write to `0xfffffb04`; the peripheral meaning remains unverified.
- E38 OS 12607218: the image maps at zero under `PowerPC:BE:32:default`. The observed branch stub at `0x100` transfers to `0x168`. Early initialization includes `li r9,0x2007`, `lis r12,0x30`, and `sth r9,0x6806(r12)`; hardware register meanings remain unknown.
- GNU-built CPU32 and PowerPC fixtures retain their exact source bytes. CPU32 `TBLU` decoding, PowerPC direct call destinations, constant-return pseudocode, relocated mappings, and legacy omitted-load behavior pass their independent checks.

Exact Evidence IDs, profile digests, image hashes, warnings, and measurement details are retained in [results.json](verification/results.json). Full bundles and failed/cancelled attempts remain in the local `.analysis` directory; no ROM images or Ghidra databases are committed.

## Other checks

- 363 focused REA source tests and 12 boundary tests passed.
- 17 coordinator tests passed, including cancellation, session reuse, failure isolation, cleanup failure, cross-target rejection, and workflow/projection provenance.
- Typechecking, the fast lint gate, changed-file formatting, and test discovery passed.
- Five actual CLI/Ghidra mapping cases passed, including split load/entry and relocated legacy behavior.
- A real coordinator MCP submission completed, with paged and exact evidence retrieval. The six-tool catalog also passed Windows-to-WSL stdio negotiation.

P59 startup pseudocode still reports control-flow warnings. Complete processor semantics, RAM/peripheral maps, runtime behavior, hardware testing, and replacement engine-management firmware remain further work. The verification pipeline executes analysis tools and never executes the controller firmware.
