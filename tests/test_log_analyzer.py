import tempfile
import os
import unittest

from src.log_analyzer import (
    analyze_logs,
    detect_suspicious_ips,
    generate_report
)

class TestLogAnalyzer(unittest.TestCase):

    def test_analyze_logs(self):
        login_counts, failed_attempts = analyze_logs("data/sample_auth.log")

        self.assertEqual(login_counts["SUCCESS"], 5)
        self.assertEqual(login_counts["FAILED"], 9)

        self.assertEqual(failed_attempts["203.0.113.25"], 3)
        self.assertEqual(failed_attempts["198.51.100.42"], 3)
        self.assertEqual(failed_attempts["203.0.113.50"], 3)

    def test_detect_suspicious_ips(self):
        failed_attempts = {
            "192.0.2.10": 2,
            "203.0.113.25": 4,
            "198.51.100.42": 7
        }

        suspicious = detect_suspicious_ips(failed_attempts, 5)

        self.assertEqual(
            suspicious,
            {"198.51.100.42": 7}
        )


    def test_malformed_records_are_skipped(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as file:
            file.write("2026-11-14 09:00:12,admin,192.0.2.10,SUCCESS\n")
            file.write("INVALID RECORD\n")
            file.write("2026-11-14 09:05:18,admin,203.0.113.25,FAILED\n")
            file.write("2026-11-14 09:06:00,user1,192.0.2.15,UNKNOWN\n")
            temp_path = file.name

        try:
            login_counts, failed_attempts = analyze_logs(temp_path)

            self.assertEqual(login_counts["SUCCESS"], 1)
            self.assertEqual(login_counts["FAILED"], 1)
            self.assertEqual(failed_attempts, {"203.0.113.25": 1})
        finally:
            os.remove(temp_path)

    def test_missing_file(self):
        login_counts, failed_attempts = analyze_logs("data/nonexistent.log")

        self.assertEqual(login_counts, {"SUCCESS": 0, "FAILED": 0})
        self.assertEqual(failed_attempts, {})

    
    def test_generate_report(self):
        login_counts = {
            "SUCCESS": 5,
            "FAILED": 9
        }

        failed_attempts = {
            "203.0.113.25": 3,
            "198.51.100.42": 3
        }

        suspicious_ips = {
            "203.0.113.25": 3,
            "198.51.100.42": 3
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = os.path.join(temp_dir, "test_report.txt")

            generate_report(
                login_counts,
                failed_attempts,
                suspicious_ips,
                output_file
            )

            with open(output_file, "r") as report:
                content = report.read()

            self.assertIn("Successful Logins: 5", content)
            self.assertIn("Failed Logins: 9", content)
            self.assertIn("203.0.113.25: 3 failed attempts", content)



if __name__ == "__main__":
    unittest.main()