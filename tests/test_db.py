import os
import tempfile
import unittest


class TestDbPersistence(unittest.TestCase):
    def setUp(self):
        # Point THREATSCOPE_DB_PATH at a fresh temp file BEFORE importing db,
        # so each test run is isolated.
        self._tmpdir = tempfile.mkdtemp()
        self._db_path = os.path.join(self._tmpdir, "test.db")
        os.environ["THREATSCOPE_DB_PATH"] = self._db_path

        import importlib
        import config
        importlib.reload(config)
        global db
        import db as db_module
        importlib.reload(db_module)
        db = db_module
        db.init_db()

    def tearDown(self):
        os.environ.pop("THREATSCOPE_DB_PATH", None)

    def test_record_and_fetch(self):
        db.record_investigation(
            kind="IOC", ioc_value="8.8.8.8", ioc_type="IPv4",
            classification="Clean", severity="Low", result_status="VALID RESULT",
        )
        rows = db.fetch_recent(limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ioc_value"], "8.8.8.8")

    def test_dashboard_counts_reflect_persisted_data_only(self):
        db.record_investigation(kind="IOC", ioc_value="1.1.1.1", classification="Malicious", severity="Critical", result_status="VALID RESULT")
        db.record_investigation(kind="IOC", ioc_value="2.2.2.2", classification="Clean", severity="Low", result_status="VALID RESULT")
        counts = db.fetch_dashboard_counts()
        self.assertEqual(counts["total"], 2)
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(counts["suspicious"], 1)

    def test_survives_reconnect(self):
        db.record_investigation(kind="LOG", ioc_value="upload.log", classification="Suspicious", severity="High", result_status="VALID RESULT")
        # Simulate a fresh page load / new sqlite3.connect() call.
        rows_again = db.fetch_recent(limit=10)
        self.assertEqual(len(rows_again), 1)


if __name__ == "__main__":
    unittest.main()
