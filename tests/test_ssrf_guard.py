from __future__ import annotations

import unittest

from mcp_tool_guard.guards.ssrf_guard import check_url
from mcp_tool_guard.policy import NetworkPolicy


class TestSsrfGuard(unittest.TestCase):
    def test_obfuscated_ips_schemes_and_userinfo_blocked(self) -> None:
        pol = NetworkPolicy(allowed_schemes=["https", "http"])
        attacks = [
            "http://127.0.0.1:8080/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:8000/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://[64:ff9b::169.254.169.254]/",
            "http://[2002:7f00:0001::]/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://127.1/",
            "http://169.254.43518/",
            "http://localhost/admin",
            "http://metadata.google.internal/computeMetadata/v1/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "http://trusted.com@127.0.0.1/",
            "https://docs.python.org/\n",
        ]
        for url in attacks:
            self.assertTrue(check_url(url, pol), f"Missed SSRF: {url!r}")

    def test_dns_rebinding_fail_closed_and_domain_allowlist(self) -> None:
        def _rebinding_resolver(host: str) -> list[str]:
            if host == "evil-rebind.example":
                return ["10.0.0.12"]
            if host == "broken-dns.example":
                raise OSError("NXDOMAIN")
            return ["93.184.216.34"]

        pol = NetworkPolicy(resolve_dns=True)
        res_rebind = check_url("https://evil-rebind.example/data", pol, resolver=_rebinding_resolver)
        self.assertTrue(any(f.code == "SSRF_DNS_REBINDING_BLOCKED" for f in res_rebind))

        res_fail = check_url("https://broken-dns.example/data", pol, resolver=_rebinding_resolver)
        self.assertTrue(any(f.code == "DNS_RESOLUTION_FAILED" for f in res_fail))

        self.assertEqual(
            check_url("https://docs.example.org/guide", pol, resolver=_rebinding_resolver),
            [],
        )

        pol_allow = NetworkPolicy(allowed_domains=["github.com"], denied_domains=["gist.github.com"])
        self.assertEqual(check_url("https://api.github.com/repos", pol_allow), [])
        self.assertTrue(check_url("https://gist.github.com/secret", pol_allow))
        self.assertTrue(check_url("https://evil.com/", pol_allow))


if __name__ == "__main__":
    unittest.main()
