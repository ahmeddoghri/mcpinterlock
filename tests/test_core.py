import copy
import unittest

from mcpinterlock.core import AuditStore, DEMO, analyze


class MCPInterlockTest(unittest.TestCase):
    def test_blocks_metadata_ssrf_and_path_escape(self):
        result = analyze(DEMO)
        self.assertEqual(result["decision"], "deny")
        self.assertEqual({item["code"] for item in result["violations"]}, {"network_target_blocked", "path_outside_workspace"})

    def test_allows_scoped_file_read(self):
        payload = copy.deepcopy(DEMO)
        payload["request"]["params"] = {"name": "read_file", "arguments": {"path": "/tmp/mcp-workspace/report.txt"}}
        result = analyze(payload)
        self.assertEqual(result["decision"], "allow")
        store = AuditStore()
        store.record(result)
        self.assertEqual(store.count(), 1)


if __name__ == "__main__":
    unittest.main()
