import os
import unittest
from unittest.mock import patch

from whitecell.cli import WhiteCellCLI


class CLIGroqCommandTests(unittest.TestCase):
    def setUp(self):
        self.cli = WhiteCellCLI()

    @patch("whitecell.cli.console.print")
    def test_explain_command_requires_arguments(self, mock_print):
        result = self.cli.handle_command("explain", [])
        self.assertTrue(result)
        mock_print.assert_called()

    @patch("whitecell.cli.console.print")
    @patch("whitecell.cli.groq_client.get_explanation", return_value="explanation")
    def test_explain_command_routes_to_groq(self, mock_explain, mock_print):
        with patch.dict(os.environ, {"WHITECELL_ENABLE_GROQ": "1"}):
            result = self.cli.handle_command("explain", ["test", "query"])
        self.assertTrue(result)
        mock_explain.assert_called_once_with("test query")
        mock_print.assert_called_with("explanation")

    @patch("whitecell.cli.console.print")
    def test_strategy_command_respects_feature_flag(self, mock_print):
        with patch.dict(os.environ, {"WHITECELL_ENABLE_GROQ": "0"}):
            result = self.cli.handle_command("strategy", ["ransomware"])
        self.assertTrue(result)
        mock_print.assert_called_with("[yellow]Groq commands are disabled by feature flag.[/yellow]")

    @patch("whitecell.cli.get_session_logs", return_value=[{"id": 1}, {"id": 2}, {"id": 3}])
    def test_persisted_log_count_uses_file_backed_logs(self, _mock_logs):
        self.assertEqual(self.cli.persisted_log_count(), 3)

    @patch("whitecell.cli.groq_client.is_configured", return_value=True)
    def test_groq_status_text_marks_placeholder_behavior(self, _mock_configured):
        with patch.dict(os.environ, {"WHITECELL_ENABLE_GROQ": "1"}):
            status = self.cli.groq_status_text()
        self.assertIn("placeholder responses", status)

    def test_suggest_command_for_typo(self):
        self.assertEqual(self.cli.suggest_command("stats"), "status")
        self.assertIsNone(self.cli.suggest_command("completelyunknown"))

    def test_format_timestamp_handles_iso_and_invalid_values(self):
        formatted = self.cli.format_timestamp("2024-01-01T10:20:30")
        self.assertEqual(formatted, "2024-01-01 10:20:30")
        self.assertEqual(self.cli.format_timestamp("not-a-date"), "not-a-date")
        self.assertEqual(self.cli.format_timestamp(""), "-")

    @patch("whitecell.cli.console.print")
    def test_crew_spawn_and_duplicate_handling(self, mock_print):
        result = self.cli.handle_command("crew", ["spawn", "alpha", "analyst"])
        self.assertTrue(result)
        self.assertIsNotNone(self.cli.state.get_helper("alpha"))

        duplicate_result = self.cli.handle_command("crew", ["spawn", "alpha", "analyst"])
        self.assertTrue(duplicate_result)
        mock_print.assert_called()

    @patch("whitecell.cli.console.print")
    def test_crew_report_no_helpers(self, mock_print):
        self.cli.state.helper_crew.clear()
        self.cli.state.helper_activity.clear()
        result = self.cli.handle_command("crew", ["report"])
        self.assertTrue(result)
        mock_print.assert_called()

    @patch("whitecell.cli.time.sleep", return_value=None)
    def test_crew_watch_command(self, _mock_sleep):
        result = self.cli.handle_command("crew", ["watch", "1"])
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
