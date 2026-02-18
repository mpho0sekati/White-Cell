import json
import tempfile
import unittest
from pathlib import Path

from whitecell.engine import get_session_logs, handle_input, initialize_logging, parse_command
import whitecell.engine as engine
from whitecell.risk import calculate_risk
from whitecell.state import global_state


class RiskUnitTests(unittest.TestCase):
    def test_calculate_risk_low_medium_high_bands(self):
        low = calculate_risk({"threat_type": "phishing", "severity": 1})
        medium = calculate_risk({"threat_type": "phishing", "severity": 6})
        high = calculate_risk({"threat_type": "ransomware", "severity": 10})

        self.assertEqual(low["risk_level"], "low")
        self.assertEqual(medium["risk_level"], "medium")
        self.assertEqual(high["risk_level"], "high")

    def test_calculate_risk_clamps_severity(self):
        below = calculate_risk({"threat_type": "malware", "severity": -5})
        above = calculate_risk({"threat_type": "malware", "severity": 99})

        self.assertGreaterEqual(below["risk_score"], 0)
        self.assertLessEqual(above["risk_score"], 100)


class EngineIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.logs_dir = Path(self.temp_dir.name)
        self.logs_file = self.logs_dir / "threats.json"

        # Patch logging targets
        self.original_logs_dir = engine.LOGS_DIR
        self.original_logs_file = engine.LOGS_FILE
        engine.LOGS_DIR = self.logs_dir
        engine.LOGS_FILE = self.logs_file

        # Reset shared state for deterministic tests
        global_state.command_mode = False
        global_state.last_threat = {}
        global_state.clear_logs()
        global_state.session_active = True

    def tearDown(self):
        engine.LOGS_DIR = self.original_logs_dir
        engine.LOGS_FILE = self.original_logs_file
        self.temp_dir.cleanup()

    def test_parse_command_unit(self):
        command, args = parse_command("status now please")
        self.assertEqual(command, "status")
        self.assertEqual(args, ["now", "please"])

        command, args = parse_command("   ")
        self.assertEqual(command, "")
        self.assertEqual(args, [])

    def test_handle_input_safe_flow_no_command_mode(self):
        response = handle_input("hello world")
        self.assertIn("You said", response)
        self.assertFalse(global_state.command_mode)

    def test_handle_input_threat_flow_detect_risk_log_response(self):
        response = handle_input("We are under ransomware attack and files are encrypted")

        self.assertTrue(global_state.command_mode)
        self.assertEqual(global_state.last_threat.get("threat_type"), "ransomware")
        self.assertIn("THREAT DETECTED", response)
        self.assertIn("COMMAND MODE ACTIVE", response)

        logs = json.loads(self.logs_file.read_text())
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["threat_type"], "ransomware")
        self.assertIn("risk_score", logs[0])

    def test_log_file_corruption_is_handled(self):
        initialize_logging()
        self.logs_file.write_text("{invalid_json")

        response = handle_input("phishing email asks me to verify credentials")
        self.assertIn("THREAT DETECTED", response)

        logs = get_session_logs()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["threat_type"], "phishing")

    def test_command_mode_transition_activate_and_clear(self):
        self.assertFalse(global_state.command_mode)
        handle_input("Detected malware on workstation")
        self.assertTrue(global_state.command_mode)

        global_state.deactivate_command_mode()
        self.assertFalse(global_state.command_mode)


if __name__ == "__main__":
    unittest.main()
