# Parallel PCM investigations

This package runs static investigations through a bounded pool of independent
REA MCP processes. A worker keeps its REA process alive across jobs, accesses
one Program serially, exports that job's Evidence, and closes the target before
taking another job. A close failure retires the process before it is reused.

Python 3.12 and `mcp==1.30.0` are used by the verified WSL environment. REA and
Ghidra are separate, caller-installed tools. Use the patched REA checkout with
CPU32, raw big-endian PowerPC, and separate `load_address` support.

From the directory containing `coordinator/`:

```bash
/opt/pcm-reversal/venv/bin/python -m coordinator \
  coordinator/examples/two_controllers.json \
  --output .analysis/investigations

/opt/pcm-reversal/venv/bin/python -m unittest discover -s coordinator/tests -v
```

The example uses explicitly selected local images and hashes. Change executable,
image and Ghidra paths for your machine. Paths in a plan are resolved relative to
the plan file. A SHA-256 mismatch prevents the target from being opened. The
execution entry and mapped image range are checked before analysis.

`workers` bounds concurrently active REA processes. Optional positive
`startup_timeout`, `call_timeout`, and `cleanup_timeout` values are seconds;
defaults are 120, 600, and 60. A missing `load_address` preserves REA's legacy
load-at-entry interpretation, and is sent to REA as an omission.

Each run receives a unique output directory containing:

- `plan.json`: explicit job plans and executable coordinates, excluding environment values.
- `events.jsonl`: job/worker start and finish events with monotonic timestamps.
- `report.json`: completion state, peak active jobs, provenance and per-job reports.
- `jobs/<id>/calls/`: complete structured responses, arguments and timing per call.
- `jobs/<id>/evidence.json`: the canonical REA Evidence bundle, exported before close.
- `workers/<id>/`: stderr and owned Linux PID/start-ticks/boot-id records.
- `findings.jsonl` and `unknowns.jsonl`: evidence coordinates and unresolved questions.

Completed means the requested observations were collected, exported, and closed
successfully with unchanged source bytes. It does not mean research questions
are answered or engine behavior is verified. An analyst or explicit verifier
must link each conclusion to the observations that support it. Pseudocode and
static references do not establish runtime behavior.

Every Evidence reply is checked against the image hash, processor/load/entry
selection and concrete Ghidra identity. REA composed workflow commitments retain
their upstream engine profile; workflow and engine digests are preserved
separately. The original records remain intact for REA's own authentication and
comparison tools. There is no cross-run result cache.

## Agent access through MCP

```bash
/opt/pcm-reversal/venv/bin/python -m coordinator.mcp_server --max-workers 4
```

This stdio server exposes `submit_investigation`, `investigation_status`,
`cancel_investigation`, `read_investigation_job`, `read_investigation_call`, and
`read_investigation_evidence`. Submission returns immediately. `--max-workers`
is one global REA-process budget shared by all investigations submitted to the
server. Shutdown cancels active investigations and awaits their cleanup.

Job reads return compact metadata and call indexes. Read an individual call for
its complete response. Evidence reads page metadata by default; an exact
`evidence_id` selects one complete retained record. Arbitrary shell/debugger
operations are outside this coordinator's static investigation tool surface.

Cancelling an investigation preserves completed observations, attempts Evidence
export and target close, and records cancelled jobs. A failed job does not cancel
unrelated jobs. Startup/transport failures are reported per job; an uncertain
target close prevents that worker session from being reused.
