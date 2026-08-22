"""
Targeted tests for the UI refinement pass: dashboard charts render with
real persisted data, Recent Investigations renders as compact rows with a
working "View ->" navigation action, and the sidebar-toggle CSS fix is
actually present in the page (regression test for the original bug).
"""
import os
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

import api_client

APP_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


class TestDashboardUIRefinement(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        os.environ["THREATSCOPE_DB_PATH"] = os.path.join(self._tmpdir, "ui_smoke.db")
        for var in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"):
            os.environ.pop(var, None)

    def tearDown(self):
        os.environ.pop("THREATSCOPE_DB_PATH", None)

    def _seed_history(self):
        import importlib
        import config
        importlib.reload(config)
        import db as db_module
        importlib.reload(db_module)
        db_module.init_db()
        db_module.record_investigation(
            kind="IOC", ioc_value="6.6.6.6", ioc_type="IPv4",
            classification="Malicious", severity="Critical", result_status="VALID RESULT",
            provider_summary={"VirusTotal": "OK", "AbuseIPDB": "OK"},
        )
        db_module.record_investigation(
            kind="IOC", ioc_value="example.com", ioc_type="Domain",
            classification="Clean", severity="Low", result_status="VALID RESULT",
            provider_summary={"VirusTotal": "OK"},
        )
        db_module.record_investigation(
            kind="LOG", ioc_value="events.log", classification="Suspicious",
            severity="High", result_status="VALID RESULT",
        )

    def test_dashboard_renders_charts_and_recent_rows_with_real_data(self):
        self._seed_history()
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        self.assertFalse(at.exception, f"Dashboard crashed with real data: {at.exception}")

        # Charts: at least one plotly chart element should be present (bar
        # + donut) once there's classification data to plot.
        self.assertGreaterEqual(len(at.get("plotly_chart")), 2)

        # Recent Investigations: compact-row markup should include the
        # investigated values and pill badges, not the old giant markdown
        # line format.
        body = " ".join(m.value for m in at.markdown)
        self.assertIn("6.6.6.6", body)
        self.assertIn("example.com", body)
        self.assertIn("pill-critical", body)  # severity/classification pill rendered

        # "View ->" action buttons exist, one per recent-investigation row.
        view_buttons = [b for b in at.button if b.label == "View →"]
        self.assertEqual(len(view_buttons), 3)

    def test_view_button_navigates_to_history_page(self):
        self._seed_history()
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        view_buttons = [b for b in at.button if b.label == "View →"]
        self.assertTrue(view_buttons)
        view_buttons[0].click().run(timeout=30)
        self.assertFalse(at.exception)
        self.assertEqual(at.session_state["nav_page"], "Investigation History")

    def test_sidebar_toggle_css_present_and_header_not_blanket_hidden(self):
        """Regression test for the sidebar-trap bug: the raw CSS emitted by
        the app must not blanket-hide the header element that hosts the
        sidebar re-open control, and must explicitly force the
        expand/collapse controls visible."""
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        css = " ".join(m.value for m in at.markdown if "<style>" in m.value)
        self.assertIn("stExpandSidebarButton", css)
        self.assertIn("visibility:visible", css.replace(" ", ""))
        # The old bug was a bare "header{ visibility:hidden; }" rule that
        # hides the whole header (and the sidebar re-open control inside
        # it). That exact bare-selector rule must not be present -- only
        # the scoped [data-testid="stHeader"]{ background:transparent }
        # rule should touch the header element now.
        self.assertNotIn("header{ visibility:hidden", css)
        self.assertNotIn("header{visibility:hidden", css)

    def test_all_pages_still_reachable_after_ui_change(self):
        at = AppTest.from_file(APP_PATH)
        at.run(timeout=30)
        for target in ["IOC Investigation", "Log Analysis", "File Analysis",
                        "MITRE ATT&CK", "Investigation History", "Settings / Provider Status", "Dashboard"]:
            at.sidebar.radio[0].set_value(target).run(timeout=30)
            self.assertFalse(at.exception, f"Page '{target}' crashed after UI refinement: {at.exception}")


if __name__ == "__main__":
    unittest.main()
