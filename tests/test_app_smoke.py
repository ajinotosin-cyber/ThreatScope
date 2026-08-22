"""
End-to-end smoke test using Streamlit's official AppTest harness. Drives
app.py itself (not just the underlying modules) to confirm the UI doesn't
crash across every page and, critically, that a provider failure doesn't
take down the whole app (Phase 13 requirement).
"""
import os
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

import api_client

APP_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


class TestAppSmoke(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        os.environ["THREATSCOPE_DB_PATH"] = os.path.join(self._tmpdir, "smoke.db")
        # Ensure no real keys leak into this test process.
        for var in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"):
            os.environ.pop(var, None)

    def tearDown(self):
        os.environ.pop("THREATSCOPE_DB_PATH", None)

    def test_dashboard_loads_with_no_data(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        self.assertFalse(at.exception, f"App raised on default load: {at.exception}")

    def test_ioc_page_with_missing_keys_does_not_crash(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        at.sidebar.radio[0].set_value("IOC Investigation").run(timeout=30)
        self.assertFalse(at.exception)
        at.text_input[0].set_value("8.8.8.8").run(timeout=30)
        self.assertFalse(at.exception, f"IOC page crashed with no keys configured: {at.exception}")
        # Should surface an honest "unavailable" status, not silently pass.
        body = " ".join(m.value for m in at.markdown)
        self.assertIn("PROVIDERS UNAVAILABLE", body)

    def test_ioc_page_invalid_input_does_not_crash(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        at.sidebar.radio[0].set_value("IOC Investigation").run(timeout=30)
        at.text_input[0].set_value("###not-an-ioc###").run(timeout=30)
        self.assertFalse(at.exception)
        body = " ".join(m.value for m in at.markdown) + " ".join(e.value for e in at.error)
        self.assertIn("INVALID IOC", body)

    @patch("api_client.virustotal_ip")
    @patch("api_client.abuseipdb_check")
    @patch("api_client.otx_ip")
    def test_ioc_page_provider_exception_does_not_crash_app(self, mock_otx, mock_abuse, mock_vt):
        """Simulates every provider failing at once -- app must degrade,
        never raise up through the Streamlit run."""
        mock_vt.return_value = api_client.ProviderResult("VirusTotal", api_client.STATUS_NETWORK_ERROR, message="down")
        mock_abuse.return_value = api_client.ProviderResult("AbuseIPDB", api_client.STATUS_RATE_LIMITED, message="429")
        mock_otx.return_value = api_client.ProviderResult("OTX", api_client.STATUS_NOT_CONFIGURED)

        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        at.sidebar.radio[0].set_value("IOC Investigation").run(timeout=30)
        at.text_input[0].set_value("1.2.3.4").run(timeout=30)
        self.assertFalse(at.exception, f"App crashed when all providers failed: {at.exception}")

    def test_mitre_page_loads(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        at.sidebar.radio[0].set_value("MITRE ATT&CK").run(timeout=30)
        self.assertFalse(at.exception)

    def test_history_page_loads_empty(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        at.sidebar.radio[0].set_value("Investigation History").run(timeout=30)
        self.assertFalse(at.exception)

    def test_settings_page_loads_and_shows_not_configured(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        at.sidebar.radio[0].set_value("Settings / Provider Status").run(timeout=30)
        self.assertFalse(at.exception)
        body = " ".join(m.value for m in at.markdown)
        self.assertIn("Not configured", body)


if __name__ == "__main__":
    unittest.main()
