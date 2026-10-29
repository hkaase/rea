import asyncio
import json
from pathlib import Path
import tempfile
import unittest

from coordinator.mcp_server import InvestigationController, create_server
from coordinator.runner import file_hash
from coordinator.tests.test_runner import FakeFactory


class ControllerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        image = self.root / "image.bin"
        image.write_bytes(bytes.fromhex("70074e75"))
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"schema_version": 1, "workers": 2, "rea": {"command": "fake"},
            "jobs": [{"id": f"job-{i}", "path": str(image), "sha256": file_hash(image), "architecture": "cpu32",
                      "load_address": "0x0", "entry_point": "0x0", "operations": [
                          {"tool": "analyze_function", "arguments": {"procedure": "0x0"}}]} for i in range(2)]}))

    def tearDown(self):
        self.temp.cleanup()

    async def test_global_budget_and_evidence_access(self):
        peer = FakeFactory(delay=.04)
        controller = InvestigationController(2, connection_factory=peer)
        first = controller.submit(str(self.config), str(self.root / "out"))["run_id"]
        second = controller.submit(str(self.config), str(self.root / "out"))["run_id"]
        await asyncio.gather(*(r["task"] for r in controller.runs.values()))
        self.assertEqual(controller.status(first)["state"], "completed")
        self.assertEqual(controller.status(second)["state"], "completed")
        self.assertEqual(peer.peak_sessions, 2)
        self.assertEqual(controller.read_job(first, "job-0")["status"], "completed")
        self.assertEqual(controller.read_call(first, "job-0", 0)["tool"], "open_binary")
        self.assertEqual(controller.read_evidence(first, "job-0")["total"], 0)
        with self.assertRaises(ValueError):
            controller.read_call(first, "../outside", 0)
        await controller.close()

    async def test_cancel_queued_and_running_investigation(self):
        peer = FakeFactory(delay=30)
        controller = InvestigationController(2, connection_factory=peer)
        pending = controller.submit(str(self.config), str(self.root / "out"))["run_id"]
        result = await controller.cancel(pending)
        self.assertEqual(result["state"], "cancelled")
        running = controller.submit(str(self.config), str(self.root / "out"))["run_id"]
        await asyncio.wait_for(peer.entered.wait(), 2)
        result = await controller.cancel(running)
        self.assertEqual(result["state"], "cancelled")
        self.assertEqual(peer.active_sessions, 0)
        await controller.close()

    async def test_mcp_tools_have_real_schemas(self):
        server = create_server(2)
        tools = await server.list_tools()
        self.assertEqual(len(tools), 6)
        submit = next(tool for tool in tools if tool.name == "submit_investigation")
        self.assertEqual(set(submit.inputSchema["required"]), {"config_path", "output_directory"})


if __name__ == "__main__":
    unittest.main()
