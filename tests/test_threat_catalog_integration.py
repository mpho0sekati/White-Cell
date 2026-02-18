import unittest

from whitecell.detection import detect_threat, get_threat_context
from whitecell.risk import calculate_risk


class ThreatCatalogIntegrationTests(unittest.TestCase):
    def test_detection_and_context_share_catalog_metadata(self):
        threat = detect_threat("Potential ransomware encrypted all files")
        self.assertIsNotNone(threat)
        self.assertEqual(threat["threat_type"], "ransomware")
        self.assertEqual(threat["severity"], 9)
        self.assertIn("confidence", threat)
        self.assertIn("matches", threat)
        self.assertGreater(threat["confidence"], 0)

        context = get_threat_context("ransomware")
        self.assertEqual(context["financial_impact"], 5000)
        self.assertTrue(context["popia_exposure"])

    def test_detection_returns_ranked_multi_matches(self):
        threat = detect_threat(
            "Urgent: phishing attempt with spoofed sender and verify your account link"
        )
        self.assertIsNotNone(threat)
        self.assertEqual(threat["threat_type"], "phishing")
        self.assertGreaterEqual(len(threat["matches"]), 1)
        self.assertGreaterEqual(threat["matches"][0]["confidence"], threat["matches"][-1]["confidence"])

    def test_detection_supports_typo_tolerance_and_regex_signatures(self):
        typo_threat = detect_threat("ransmware encrypted endpoints")
        self.assertIsNotNone(typo_threat)
        self.assertEqual(typo_threat["threat_type"], "ransomware")

        regex_threat = detect_threat("Potential remote code execution tied to CVE-2023-12345")
        self.assertIsNotNone(regex_threat)
        self.assertEqual(regex_threat["threat_type"], "exploit")

    def test_risk_uses_catalog_multiplier_and_compliance(self):
        risk = calculate_risk({"threat_type": "phishing", "severity": 6})
        self.assertEqual(risk["risk_score"], 48)
        self.assertTrue(risk["popia_exposure"])

    def test_unknown_threat_uses_defaults(self):
        context = get_threat_context("not_real")
        self.assertEqual(context["financial_impact"], 2000)
        self.assertFalse(context["popia_exposure"])

        risk = calculate_risk({"threat_type": "not_real", "severity": 5})
        self.assertEqual(risk["risk_score"], 50)
        self.assertEqual(risk["estimated_financial_loss"], 2000)
        self.assertFalse(risk["popia_exposure"])


if __name__ == "__main__":
    unittest.main()
