"""Exercise the public coordinator MCP surface without starting analysis engines."""

from pathlib import Path
import sys
import tempfile
import unittest

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_stdio_discovery_and_failed_submission(self):
        root = Path(__file__).resolve().parents[2]
        params = StdioServerParameters(command=sys.executable,
            args=["-m", "coordinator.mcp_server", "--max-workers", "2"], cwd=root)
        with tempfile.TemporaryFile(mode="w+") as stderr:
            async with stdio_client(params, errlog=stderr) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    self.assertEqual(len(tools.tools), 6)
                    result = await session.call_tool("submit_investigation", {
                        "config_path": str(root / "does-not-exist-investigation.json"),
                        "output_directory": str(root / ".analysis"),
                    })
                    self.assertTrue(result.isError)
                    result = await session.call_tool("investigation_status", {"run_id": "unknown"})
                    self.assertTrue(result.isError)


if __name__ == "__main__":
    unittest.main()
