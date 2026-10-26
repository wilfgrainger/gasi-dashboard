import pathlib
import unittest


INDEX = pathlib.Path(__file__).parents[1] / "index.html"


class StaticSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = INDEX.read_text(encoding="utf-8")

    def test_content_security_policy_is_present(self):
        self.assertIn('http-equiv="Content-Security-Policy"', self.html)
        self.assertIn("connect-src 'self'", self.html)
        self.assertIn("object-src 'none'", self.html)

    def test_feed_values_are_escaped_before_html_interpolation(self):
        self.assertIn("function escapeHtml(value)", self.html)
        for raw_expression in (
            "${f.name}",
            "${f.value}",
            "${it.cve_id}",
            "${it.name}",
            "${c.cve_id}",
            "${desc}",
            "${ip.ip}",
            "${ip.isp}",
            "${f.name}<span",
        ):
            self.assertNotIn(raw_expression, self.html)

        for escaped_expression in (
            "${escapeHtml(f.name)}",
            "${escapeHtml(f.value)}",
            "${escapeHtml(it.cve_id)}",
            "${escapeHtml(it.name || 'Unknown Vulnerability')}",
            "${escapeHtml(c.cve_id)}",
            "${escapeHtml(desc)}",
            "${escapeHtml(ip.ip)}",
            "${escapeHtml(ip.isp || '—')}",
        ):
            self.assertIn(escaped_expression, self.html)

    def test_numeric_feed_values_are_clamped(self):
        self.assertIn("function clampPercent(value)", self.html)
        self.assertIn("const confidence = clampPercent(ip.confidence)", self.html)
        self.assertIn("const conf = clampPercent(ip.confidence)", self.html)


if __name__ == "__main__":
    unittest.main()
