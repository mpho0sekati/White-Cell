import unittest

from whitecell.detection import detect_threat


class DetectionUnitTests(unittest.TestCase):
    def test_detect_threat_returns_none_for_safe_input(self):
        self.assertIsNone(detect_threat("How can I improve endpoint backup strategy?"))

    def test_detect_threat_uses_word_boundaries(self):
        threat = detect_threat("This is a malware incident with trojan activity")
        self.assertIsNotNone(threat)
        self.assertEqual(threat["threat_type"], "malware")
        self.assertIn("matches", threat)

    def test_detect_threat_returns_all_ranked_matches(self):
        threat = detect_threat(
            "Ransomware encrypted systems and we also see data exfiltration with records leaked"
        )
        self.assertIsNotNone(threat)
        self.assertGreaterEqual(len(threat["matches"]), 2)
        self.assertGreaterEqual(threat["matches"][0]["confidence"], threat["matches"][-1]["confidence"])


if __name__ == "__main__":
    unittest.main()
