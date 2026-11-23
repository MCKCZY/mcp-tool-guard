from __future__ import annotations

import unittest

from mcp_tool_guard.guards.dlp_guard import redact_secrets, scan_secrets, shannon_entropy
from mcp_tool_guard.policy import DlpPolicy


class TestDlpGuard(unittest.TestCase):
    def test_detects_and_redacts_multiple_secret_types(self) -> None:
        pol = DlpPolicy()
        k1 = "sk-" + "proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"
        k2 = "ghp_" + "9X8Y7Z6W5V4U3T2S1R0Q9P8O7N6M5L4K3J2I"
        k3 = "AKIA" + "IOSFODNN7EXAMPLE"
        k4 = "postgres://admin:P@ssw0rd!2026@db.internal:5432/app"
        k5 = "api_key='X9#kM2vP8qL4wZ7nB5cJ1hF6rT3yU0dA'"
        payload = f"1:{k1}\n2:{k2}\n3:{k3}\n4:{k4}\n5:{k5}"

        redacted, findings = redact_secrets(payload, pol)
        self.assertEqual(len(findings), 5)
        for raw in (k1, k2, k3, "P@ssw0rd!2026", "X9#kM2vP8qL4wZ7nB5cJ1hF6rT3yU0dA"):
            self.assertNotIn(raw, redacted)
        self.assertIn("[REDACTED:OPENAI_KEY:", redacted)
        self.assertIn("[REDACTED:GITHUB_TOKEN:", redacted)
        self.assertIn("[REDACTED:AWS_ACCESS_KEY:", redacted)
        self.assertIn("[REDACTED:DB_URL_CREDS:", redacted)
        self.assertIn("[REDACTED:HIGH_ENTROPY_SECRET:", redacted)

    def test_low_false_positive_on_uuids_placeholders_and_paths(self) -> None:
        pol = DlpPolicy()
        benign = "\n".join(
            [
                "trace_id=550e8400-e29b-41d4-a716-446655440000",
                "api_key=YOUR_API_KEY_HERE_REPLACE_ME",
                "sha=a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4",
                "src_path=/home/user/workspace/project/src/auth/jwt_verify.py",
                "status=ok latency=12.3ms",
            ]
        )
        self.assertEqual(scan_secrets(benign, pol), [])
        self.assertGreater(shannon_entropy("X9#kM2vP8qL4wZ7nB5cJ1hF6rT3yU0dA"), 4.3)
        self.assertEqual(shannon_entropy(""), 0.0)


if __name__ == "__main__":
    unittest.main()
