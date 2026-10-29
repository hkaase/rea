import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import tempfile
import unittest

from coordinator.runner import Coordinator, file_hash, validate_config


class FakePeer:
    def __init__(self, owner):
        self.owner = owner
        self.identity = {"pid": 123, "start_ticks": 1, "boot_id": "test"}
        self.current = None

    async def call(self, tool, arguments):
        self.owner.calls.append((tool, arguments))
        if tool == "open_binary":
            self.current = dict(arguments, sha256=file_hash(Path(arguments["path"])))
            return {"is_error": False, "structured": {"result": self.current}}
        if tool == "binary_session":
            return {"is_error": False, "structured": {"result": self.current}}
        if tool == "close_binary":
            self.owner.closes += 1
            self.current = None
            return {"is_error": False, "structured": {"result": None}}
        if tool == "export_evidence_bundle":
            Path(arguments["path"]).write_text('{"records": []}')
            return {"is_error": False, "structured": {"result": {"records": 1}}}
        if tool == "analyze_function":
            self.owner.entered.set()
            await asyncio.sleep(self.owner.delay)
            if arguments.get("procedure") == "fail":
                return {"is_error": True, "structured": {"error": "selected failure"}}
            if arguments.get("procedure") == "structured-fail":
                return {"is_error": False, "structured": {"ok": False, "error": "failed"}}
        digest = "0" * 64 if self.owner.wrong_source else self.current["sha256"]
        profile = {key: self.current[key] for key in ["architecture", "entry_point", "load_address"] if key in self.current}
        profile["language_id"] = "68000:BE:32:CPU32" if self.current["architecture"] == "cpu32" else "PowerPC:BE:32:default"
        return {"is_error": False, "structured": {
            "evidence_id": "ev_" + "1" * 64,
            "subject": {"digest": {"sha256": digest}},
            "provider": {"id": "ghidra"},
            "analysis_profile": {"provider": {"id": "ghidra"}, "digest": "2" * 64, "parameters": profile},
            "normalized_result": {"observed": True}, "limitations": ["Static only"],
        }}


class FakeFactory:
    def __init__(self, delay=.02, wrong_source=False):
        self.delay = delay
        self.wrong_source = wrong_source
        self.calls = []
        self.closes = 0
        self.entered = asyncio.Event()
        self.sessions = 0
        self.active_sessions = 0
        self.peak_sessions = 0

    @asynccontextmanager
    async def __call__(self, config, directory):
        self.sessions += 1
        self.active_sessions += 1
        self.peak_sessions = max(self.peak_sessions, self.active_sessions)
        try:
            yield FakePeer(self)
        finally:
            self.active_sessions -= 1


class PoolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.binary = self.root / "source.bin"
        self.binary.write_bytes(bytes.fromhex("70074e75"))

    def tearDown(self):
        self.temp.cleanup()

    def config(self, count=1, workers=2):
        return {"schema_version": 1, "workers": workers,
            "rea": {"command": "unused", "env": {"SECRET_EXPLICIT": "not-in-report"}},
            "jobs": [{"id": f"job-{i}", "path": str(self.binary), "sha256": file_hash(self.binary),
                "architecture": "cpu32", "load_address": "0x0", "entry_point": "0x0",
                "questions": ["What remains unknown?"],
                "operations": [{"tool": "analyze_function", "arguments": {"procedure": "0x0"}}]}
                for i in range(count)]}

    async def test_bounded_parallelism_and_persistent_session_reuse(self):
        peer = FakeFactory(delay=.04)
        coordinator = Coordinator(self.config(5), self.root / "out", connection_factory=peer)
        report = await coordinator.run()
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["peak_active_jobs"], 2)
        self.assertEqual(peer.sessions, 2)
        self.assertEqual(peer.closes, 5)
        self.assertEqual(peer.active_sessions, 0)
        self.assertTrue(all(j["source_unchanged"] for j in report["jobs"]))
        self.assertNotIn("not-in-report", (coordinator.run_dir / "plan.json").read_text())
        self.assertEqual(file_hash(self.binary), report["jobs"][0]["source_sha256_before"])

    async def test_failure_isolated_and_evidence_preserved_before_close(self):
        config = self.config(3, workers=1)
        config["jobs"][0]["operations"][0]["arguments"]["procedure"] = "fail"
        config["jobs"][1]["operations"][0]["arguments"]["procedure"] = "structured-fail"
        peer = FakeFactory()
        report = await Coordinator(config, self.root / "out", connection_factory=peer).run()
        self.assertEqual([j["status"] for j in report["jobs"]], ["failed", "failed", "completed"])
        self.assertEqual(peer.closes, 3)
        tools = [tool for tool, _ in peer.calls]
        self.assertLess(tools.index("export_evidence_bundle"), tools.index("close_binary"))
        self.assertTrue((Path(report["run_directory"]) / "jobs/job-0/evidence.json").exists())

    async def test_wrong_source_stops_before_open(self):
        config = self.config()
        config["jobs"][0]["sha256"] = "0" * 64
        peer = FakeFactory()
        report = await Coordinator(config, self.root / "out", connection_factory=peer).run()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(peer.calls, [])
        self.assertTrue(report["jobs"][0]["source_unchanged"])

    async def test_cross_target_evidence_is_refused(self):
        peer = FakeFactory(wrong_source=True)
        report = await Coordinator(self.config(), self.root / "out", connection_factory=peer).run()
        self.assertEqual(report["status"], "failed")
        self.assertIn("another source", report["jobs"][0]["error"]["message"])
        self.assertEqual(peer.closes, 1)

    async def test_cancellation_exports_and_closes_active_sessions(self):
        peer = FakeFactory(delay=30)
        coordinator = Coordinator(self.config(3), self.root / "out", connection_factory=peer)
        task = asyncio.create_task(coordinator.run())
        await asyncio.wait_for(peer.entered.wait(), 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        report = json.loads((coordinator.run_dir / "report.json").read_text())
        self.assertEqual(report["status"], "cancelled")
        self.assertEqual(peer.active_sessions, 0)
        self.assertEqual(peer.closes, 2)
        self.assertEqual(coordinator.active, 0)

    async def test_deadline_failure_still_closes(self):
        config = self.config()
        config["call_timeout"] = .01
        peer = FakeFactory(delay=.1)
        report = await Coordinator(config, self.root / "out", connection_factory=peer).run()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["jobs"][0]["error"]["type"], "TimeoutError")
        self.assertEqual(peer.closes, 1)

    async def test_legacy_omitted_load_address_is_not_sent(self):
        config = self.config()
        del config["jobs"][0]["load_address"]
        peer = FakeFactory()
        report = await Coordinator(config, self.root / "out", connection_factory=peer).run()
        self.assertEqual(report["status"], "completed")
        self.assertNotIn("load_address", peer.calls[0][1])

    async def test_uncertain_close_retires_worker_before_next_job(self):
        owner = FakeFactory()
        original = FakePeer.call
        fail_close = True

        class CloseFailurePeer(FakePeer):
            async def call(self, tool, arguments):
                nonlocal fail_close
                if tool == "close_binary" and fail_close:
                    fail_close = False
                    return {"is_error": True, "structured": {"error": "cleanup uncertain"}}
                return await original(self, tool, arguments)

        @asynccontextmanager
        async def factory(config, directory):
            owner.sessions += 1
            yield CloseFailurePeer(owner)

        report = await Coordinator(self.config(2, workers=1), self.root / "out", connection_factory=factory).run()
        self.assertEqual([j["status"] for j in report["jobs"]], ["failed", "completed"])
        self.assertEqual(owner.sessions, 2)

    async def test_composed_evidence_retains_upstream_identity(self):
        owner = FakeFactory()

        class WorkflowPeer(FakePeer):
            async def call(self, tool, arguments):
                reply = await super().call(tool, arguments)
                value = reply["structured"]
                if tool == "binary_overview":
                    engine = value["analysis_profile"]
                    value["provider"] = {"id": "rea-workflow"}
                    value["analysis_profile"] = {"provider": {"id": "rea-workflow"}, "digest": "3" * 64,
                        "parameters": {"upstream_analysis_profile": engine}}
                return reply

        @asynccontextmanager
        async def factory(config, directory):
            yield WorkflowPeer(owner)

        report = await Coordinator(self.config(), self.root / "out", connection_factory=factory).run()
        self.assertEqual(report["status"], "completed")
        self.assertEqual(len(report["jobs"][0]["analysis_profile_digests"]), 2)
        self.assertEqual(len(report["jobs"][0]["engine_profile_digests"]), 1)

    async def test_summary_projection_binds_known_source_profile_and_parent(self):
        owner = FakeFactory()

        class SummaryPeer(FakePeer):
            async def call(self, tool, arguments):
                reply = await super().call(tool, arguments)
                if tool == "list_procedures":
                    value = reply["structured"]
                    parent = "ev_" + "4" * 64
                    value.update({"provider": {"id": "rea-analysis-view"}, "analysis_profile": None,
                        "parameters": {"parent_evidence_id": parent}, "evidence_links": [parent],
                        "normalized_result": {"source_provider": {"id": "ghidra"},
                            "source_analysis_profile_digest": "2" * 64, "parent_evidence_id": parent,
                            "parent_digest": "4" * 64, "artifact": {"sha256": self.current["sha256"]}}})
                return reply

        @asynccontextmanager
        async def factory(config, directory):
            yield SummaryPeer(owner)

        config = self.config()
        config["jobs"][0]["operations"] = [{"tool": "list_procedures", "arguments": {"detail": "summary"}}]
        report = await Coordinator(config, self.root / "out", connection_factory=factory).run()
        self.assertEqual(report["status"], "completed")
        self.assertEqual(len(report["jobs"][0]["projection_sources"]), 1)

    async def test_summary_projection_rejects_unknown_source_profile(self):
        owner = FakeFactory()

        class WrongSummaryPeer(FakePeer):
            async def call(self, tool, arguments):
                reply = await super().call(tool, arguments)
                if tool == "list_procedures":
                    reply["structured"].update({"provider": {"id": "rea-analysis-view"}, "analysis_profile": None,
                        "normalized_result": {"source_analysis_profile_digest": "5" * 64}})
                return reply

        @asynccontextmanager
        async def factory(config, directory):
            yield WrongSummaryPeer(owner)

        config = self.config()
        config["jobs"][0]["operations"] = [{"tool": "list_procedures", "arguments": {"detail": "summary"}}]
        report = await Coordinator(config, self.root / "out", connection_factory=factory).run()
        self.assertEqual(report["status"], "failed")
        self.assertIn("unbound source", report["jobs"][0]["error"]["message"])

    async def test_transport_teardown_failure_is_not_reported_as_success(self):
        owner = FakeFactory()

        @asynccontextmanager
        async def factory(config, directory):
            yield FakePeer(owner)
            raise RuntimeError("owned transport cleanup failed")

        report = await Coordinator(self.config(), self.root / "out", connection_factory=factory).run()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["jobs"][0]["status"], "completed")
        self.assertEqual(report["worker_errors"][0]["type"], "RuntimeError")

    def test_rejects_duplicate_jobs_or_execution_tools(self):
        config = self.config()
        config["jobs"].append(dict(config["jobs"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            validate_config(config)
        config = self.config()
        config["jobs"][0]["operations"][0]["tool"] = "gdb_console"
        with self.assertRaisesRegex(ValueError, "static"):
            validate_config(config)


if __name__ == "__main__":
    unittest.main()
