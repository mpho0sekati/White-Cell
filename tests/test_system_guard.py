import unittest
from unittest.mock import patch

from whitecell.system_guard import scan_system


class SystemGuardTests(unittest.TestCase):
    @patch("whitecell.system_guard._count_established_connections", return_value=12)
    @patch("whitecell.system_guard._collect_process_names", return_value=["python", "sshd"])
    def test_scan_system_low_risk_when_no_findings(self, _mock_proc, _mock_conn):
        result = scan_system()
        self.assertEqual(result["risk_level"], "low")
        self.assertEqual(result["findings"], [])

    @patch("whitecell.system_guard._count_established_connections", return_value=520)
    @patch("whitecell.system_guard._collect_process_names", return_value=["python", "mimikatz.exe"])
    def test_scan_system_flags_suspicious_signals(self, _mock_proc, _mock_conn):
        result = scan_system()
        self.assertEqual(result["risk_level"], "high")
        self.assertGreaterEqual(len(result["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
