import unittest

import log_parser


class TestLogParser(unittest.TestCase):
    def test_txt_detects_categories(self):
        content = (
            "2026-01-01 10:00:00 Failed login for user admin from SRC=1.2.3.4\n"
            "2026-01-01 10:00:05 Nmap scan detected from 5.6.7.8\n"
            "2026-01-01 10:00:10 sudo access attempt by user bob\n"
            "2026-01-01 10:00:15 malware signature match on host\n"
            "2026-01-01 10:00:20 normal request, nothing to see here\n"
        )
        result = log_parser.parse_log("sample.log", content.encode())
        self.assertTrue(result.parse_ok)
        self.assertEqual(result.total_events, 5)
        self.assertEqual(result.suspicious_events, 4)
        self.assertIn("Brute Force", result.category_counts)
        self.assertIn("Port Scan", result.category_counts)
        self.assertIn("Privilege Escalation", result.category_counts)
        self.assertIn("Malware Indicator", result.category_counts)
        self.assertIn("1.2.3.4", result.extracted_iocs)

    def test_csv_parsing(self):
        content = "timestamp,message\n2026-01-01,failed login attempt\n2026-01-02,all clear\n"
        result = log_parser.parse_log("events.csv", content.encode())
        self.assertTrue(result.parse_ok)
        self.assertGreaterEqual(result.suspicious_events, 1)

    def test_json_array_parsing(self):
        content = '[{"msg": "nmap scan from host"}, {"msg": "all fine"}]'
        result = log_parser.parse_log("events.json", content.encode())
        self.assertTrue(result.parse_ok)
        self.assertEqual(result.suspicious_events, 1)

    def test_json_lines_parsing(self):
        content = '{"msg": "sudo access attempt"}\n{"msg": "nothing"}\n'
        result = log_parser.parse_log("events.jsonl.json", content.encode())
        self.assertTrue(result.parse_ok)
        self.assertEqual(result.suspicious_events, 1)

    def test_malformed_json_fails_gracefully(self):
        content = "{this is not valid json at all"
        result = log_parser.parse_log("broken.json", content.encode())
        self.assertFalse(result.parse_ok)
        self.assertIn("could not be parsed", result.parse_message.lower())

    def test_empty_file(self):
        result = log_parser.parse_log("empty.txt", b"")
        self.assertFalse(result.parse_ok)

    def test_non_utf8_bytes_do_not_crash(self):
        raw = b"\xff\xfe\x00\x01 failed login attempt \x80\x81"
        result = log_parser.parse_log("weird.log", raw)
        # Must not raise; latin-1 fallback should still parse something.
        self.assertTrue(result.parse_ok or not result.parse_ok)  # never raises

    def test_clean_file_no_findings(self):
        content = "everything is fine\nstill fine\nnothing to report\n"
        result = log_parser.parse_log("clean.txt", content.encode())
        self.assertTrue(result.parse_ok)
        self.assertEqual(result.suspicious_events, 0)


if __name__ == "__main__":
    unittest.main()
