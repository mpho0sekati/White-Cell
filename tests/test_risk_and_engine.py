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
        self.logs_file = self.logs_dir / "threats.jsonl"
        self.legacy_logs_file = self.logs_dir / "threats.json"

        # Patch logging targets
        self.original_logs_dir = engine.LOGS_DIR
        self.original_logs_file = engine.LOGS_FILE
        self.original_legacy_logs_file = engine.LEGACY_LOGS_FILE
        self.original_rotation_max_bytes = engine.LOG_ROTATION_MAX_BYTES
        self.original_retention_files = engine.LOG_RETENTION_FILES

        engine.LOGS_DIR = self.logs_dir
        engine.LOGS_FILE = self.logs_file
        engine.LEGACY_LOGS_FILE = self.legacy_logs_file
        engine.LOG_ROTATION_MAX_BYTES = 1_000_000
        engine.LOG_RETENTION_FILES = 5

        # Reset shared state for deterministic tests
        global_state.command_mode = False
        global_state.last_threat = {}
        global_state.clear_logs()
        global_state.helper_crew.clear()
        global_state.helper_activity.clear()
        global_state.session_active = True

    def tearDown(self):
        engine.LOGS_DIR = self.original_logs_dir
        engine.LOGS_FILE = self.original_logs_file
        engine.LEGACY_LOGS_FILE = self.original_legacy_logs_file
        engine.LOG_ROTATION_MAX_BYTES = self.original_rotation_max_bytes
        engine.LOG_RETENTION_FILES = self.original_retention_files
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


    def test_handle_input_updates_helper_activity_when_crew_exists(self):
        global_state.spawn_helper("alpha", "incident analyst")

        handle_input("ransomware detected on backup cluster")

        self.assertTrue(global_state.helper_activity)
        self.assertEqual(global_state.helper_activity[-1]["helper"], "alpha")
        self.assertEqual(global_state.get_helper("alpha")["status"], "engaged")

    def test_handle_input_threat_flow_detect_risk_log_response(self):
        response = handle_input("We are under ransomware attack and files are encrypted")

        self.assertTrue(global_state.command_mode)
        self.assertEqual(global_state.last_threat.get("threat_type"), "ransomware")
        self.assertIn("THREAT DETECTED", response)
        self.assertIn("COMMAND MODE ACTIVE", response)

        lines = [line for line in self.logs_file.read_text().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        first_entry = json.loads(lines[0])
        self.assertEqual(first_entry["threat_type"], "ransomware")
        self.assertIn("risk_score", first_entry)
        self.assertEqual(first_entry["schema_version"], "1.0")

    def test_log_file_corruption_is_handled(self):
        initialize_logging()
        self.logs_file.write_text("{invalid_json\n")

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

    def test_log_rotation_and_retention(self):
        engine.LOG_ROTATION_MAX_BYTES = 1
        engine.LOG_RETENTION_FILES = 2

        for i in range(5):
            handle_input(f"ransomware incident {i}")

        rotated = sorted(self.logs_dir.glob("threats-*.jsonl"))
        self.assertLessEqual(len(rotated), 2)
        self.assertTrue(self.logs_file.exists())

    def test_initialize_logging_migrates_legacy_json_array(self):
        legacy_payload = [
            {
                "timestamp": "2024-01-01T00:00:00",
                "threat_type": "malware",
                "risk_score": 88,
            }
        ]
        self.legacy_logs_file.write_text(json.dumps(legacy_payload))

        initialize_logging()

        self.assertFalse(self.legacy_logs_file.exists())
        lines = [line for line in self.logs_file.read_text().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["threat_type"], "malware")
        self.assertEqual(entry["schema_version"], "1.0")


if __name__ == "__main__":
    unittest.main()
