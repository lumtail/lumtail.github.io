# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT

"""Unit tests for build.py: python3 -m unittest discover -s tests"""

import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import build  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "mandoc-1.14.6.html"


def comments_removed(text: str) -> str:
    return re.sub(r"<!--.*?-->\s*", "", text, flags=re.S)


class Normalize(unittest.TestCase):
    def assert_canonical(self, body: str, date: str) -> None:
        self.assertNotIn("<h1", body)
        self.assertNotRegex(body, r'class="(head|foot)[-"]')
        self.assertFalse(body.startswith('<div class="manual-text">'))
        self.assertIn('<h2 class="Sh" id="NAME">', body)
        self.assertRegex(date, r"^[A-Z][a-z]+ \d{1,2}, \d{4}$")

    def test_mandoc_1_14_6(self):
        body, date = build.normalize(comments_removed(FIXTURE.read_text()))
        self.assert_canonical(body, date)
        self.assertIn('<h3 class="Ss"', body)
        self.assertNotIn('<h2 class="Ss"', body)

    @unittest.skipUnless(shutil.which("mandoc"), "mandoc not installed")
    def test_installed_mandoc(self):
        source = ROOT.parent / "lumtail" / "man" / "lumtail-formats.7"
        if not source.exists():
            self.skipTest("lumtail checkout not found")
        raw = subprocess.run(["mandoc", "-Thtml", "-O", "fragment", str(source)],
                             check=True, capture_output=True, text=True).stdout
        body, date = build.normalize(raw)
        self.assert_canonical(body, date)
        self.assertIn('<h3 class="Ss"', body)


class Platforms(unittest.TestCase):
    def test_names(self):
        cases = {
            "lumtail-0.2.0-linux-x86_64.tar.gz": ("Linux", "x86-64"),
            "lumtail-0.2.0-linux-aarch64.tar.gz": ("Linux", "arm64"),
            "lumtail-0.2.0-darwin-arm64.tar.gz": ("macOS", "arm64"),
            "lumtail-0.2.0-macos-universal.tar.gz": ("macOS", "universal"),
            "lumtail-0.2.0-freebsd-amd64.tar.xz": ("FreeBSD", "x86-64"),
            "lumtail-0.2.0-linux-x86_64.tar.gz.sha256": ("Checksums & signatures", ""),
            "SHA256SUMS": ("Checksums & signatures", ""),
            "lumtail-0.2.0.tar.gz.sigstore.json": ("Checksums & signatures", ""),
            "lumtail-0.2.0-source.tar.gz": ("Source", ""),
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(build.platform_of(name), expected)


class AgentText(unittest.TestCase):
    def test_absolute_links(self):
        base = "https://github.com/lumtail/lumtail/blob/abc/docs/"
        text = "[a](safety.md#limits) [b](../contracts/x.json) [c](https://x.org/) [d](#here)"
        self.assertEqual(build.absolute_links(text, base),
                         f"[a]({base}safety.md#limits) "
                         "[b](https://github.com/lumtail/lumtail/blob/abc/contracts/x.json) "
                         "[c](https://x.org/) [d](#here)")

    def test_strip_spdx(self):
        self.assertEqual(build.strip_spdx("<!--\nSPDX-License-Identifier: MIT\n-->\n\n# Title\n"), "# Title\n")

    def test_llms_txt(self):
        ctx = {"releases": [], "docs": [("agents.md", "Agents", "how", "")],
               "manuals": [{"page": p, "name": p.rsplit(".", 1)[0], "sec": p.rsplit(".", 1)[1],
                            "summary": "s"} for p in build.PAGES]}
        text = build.llms_txt(ctx)
        self.assertTrue(text.startswith("# Lumtail\n\n> "))
        for page in build.PAGES:
            self.assertIn(f"{build.BASE_URL}man/{page}.md", text)
        for command in build.AGENT_EXAMPLES:
            self.assertIn(command, text)


class Demos(unittest.TestCase):
    def test_cast_info(self):
        import json, tempfile
        events = [[0.1, "o", "$ "], [0.2, "o", "lumtail --filter 'a=1' checko \r"],
                  [0.3, "o", "ut.log\r\n\x1b[1mINFO\x1b[0m x\r\n"], [0.4, "o", "$ clear\r\n"]]
        with tempfile.NamedTemporaryFile("w", suffix=".cast", delete=False) as f:
            f.write(json.dumps({"version": 2, "title": "Lumtail: nginx in one stream"}) + "\n")
            f.write("\n".join(json.dumps(e) for e in events) + "\n")
        try:
            title, commands = build.cast_info(Path(f.name))
        finally:
            Path(f.name).unlink()
        self.assertEqual(title, "nginx in one stream")
        self.assertEqual(commands, ["lumtail --filter 'a=1' checkout.log"])


@unittest.skipUnless(shutil.which("mandoc"), "mandoc not installed")
class FullBuild(unittest.TestCase):
    def test_agent_files(self):
        source = ROOT.parent / "lumtail"
        if not (source / "man").exists():
            self.skipTest("lumtail checkout not found")
        import tempfile, contextlib, io
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            out = Path(tmp)
            build.build(source, out)
            for path in ("llms.txt", "llms-full.txt", "download/releases.json",
                         "cli/v1/agent-schema.json", "cli/v1/LICENSE", "docs/agents.md",
                         *(f"man/{p}.md" for p in build.PAGES)):
                self.assertTrue((out / path).is_file(), path)
            page = (out / "man" / "lumtail-agent.7.html").read_text()
            self.assertIn('<link rel="alternate" type="text/markdown" href="lumtail-agent.7.md">', page)
            self.assertIn("# DESCRIPTION", (out / "man" / "lumtail-agent.7.md").read_text())


if __name__ == "__main__":
    unittest.main()
