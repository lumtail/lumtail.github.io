#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT

"""Build lumtail.github.io from a lumtail checkout.

    python3 build.py --source ../lumtail            # render with data/*.json
    python3 build.py --source ../lumtail --sync     # refresh data/*.json from GitHub first

Needs Python 3.10+ and mandoc(1). Uses only the standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import datetime as dt
import html
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

SITE = Path(__file__).resolve().parent
DATA = SITE / "data"  # overridden by --data
BASE_URL = "https://lumtail.github.io/"
REPO = "lumtail/lumtail"
GH = f"https://github.com/{REPO}"

# Manual order: command first, then file format, then the two overviews.
PAGES = ("lumtail.1", "lumtail-rules.5", "lumtail-formats.7", "lumtail-agent.7")
SECTION_NAMES = {"1": "General Commands", "5": "File Formats", "7": "Miscellaneous"}
EXTERNAL_MAN = "https://man.openbsd.org/{name}.{sec}"

# Artwork copied verbatim from lumtail/assets (MIT, see assets/LICENSE there).
ARTWORK = (
    "img/lumtail-mark-dark.svg", "img/lumtail-mark-light.svg",
    "img/lumtail-preview-dark.svg", "img/lumtail-preview-light.svg",
    "img/lumtail-preview-mobile-dark.svg", "img/lumtail-preview-mobile-light.svg",
    "img/lumtail-social.png", "img/lumtail-social.png.license",
    "img/lumtail-avatar.png", "img/lumtail-avatar.png.license",
    "img/lumtail-social.svg",
)

# Terminal recordings in lumtail/assets/demo, in the order the home page offers
# them: (file stem, switch label). Each has <stem>.gif, <stem>-mobile.gif and
# the asciinema <stem>.cast whose title and commands describe it.
DEMOS = (("read-logs", "Read"), ("follow-filter", "Follow"), ("inspect-record", "Inspect"),
         ("history-filter", "History"), ("search-speed", "Search"))
ARTWORK += tuple(f"demo/{stem}{variant}.gif{suffix}" for stem, _ in DEMOS
                 for variant in ("", "-mobile") for suffix in ("", ".license"))

FORMATS = (  # (label, manual, anchor)
    ("JSON Lines", "lumtail-formats.7", "JSON_LINES"),
    ("Suricata EVE", "lumtail-formats.7", "Suricata_EVE_alerts"),
    ("Zeek JSON", "lumtail-formats.7", "Zeek_JSON"),
    ("Kubernetes audit", "lumtail-formats.7", "Kubernetes_audit_JSON"),
    ("syslog", "lumtail-formats.7", "SYSLOG"),
    ("CEF", "lumtail-formats.7", "COMMON_EVENT_FORMAT"),
    ("LEEF", "lumtail-formats.7", "LOG_EVENT_EXTENDED_FORMAT"),
    ("Linux Audit RAW", "lumtail-formats.7", "LINUX_AUDIT_RAW"),
    ("Fail2ban", "lumtail-formats.7", "FAIL2BAN"),
    ("Apache / Nginx access", "lumtail-formats.7", "WEB_ACCESS_LOGS"),
    ("Apache / Nginx error", "lumtail-formats.7", "WEB_ERROR_LOGS"),
    ("Custom text formats", "lumtail-rules.5", "FILE_FORMAT"),
)

# Agent quick start shown in llms.txt and on the home page. The build stops if
# lumtail-agent(7) no longer contains one of these commands.
AGENT_EXAMPLES = ("lumtail --agent --limit 20 application.log",
                  "lumtail --agent --limit 20 --min-level warn application.log",
                  "lumtail --agent --limit 20 --where service=api application.log",
                  "lumtail --agent-schema")
# Guides from lumtail/docs included in llms-full.txt: (file, title, note).
AGENT_DOCS = (("agents.md", "Using Lumtail from agents", "bounded snapshots, field selection and limits"),
              ("cli-api.md", "CLI API 1", "the stable command and JSON contract for scripts"))
# CLI API 1 contract files published under cli/v1/ (MIT, see the LICENSE beside them).
CONTRACTS = ("agent-schema.json", "record-schema.json", "contract.json", "LICENSE")

# Headers written into generated files; not this file's own notice.
# REUSE-IgnoreStart
SPDX = "<!--\nSPDX-FileCopyrightText: 2026 lumtail contributors\nSPDX-License-Identifier: MIT\n-->\n"
# REUSE-IgnoreEnd
esc = html.escape
STATIC = ("assets/site.css", "assets/site.js", "favicon.svg", ".nojekyll")
CURRENT = ' aria-current="page"'


# --------------------------------------------------------------------------- GitHub sync

def github(path: str):
    request = urllib.request.Request(
        f"https://api.github.com/{path}",
        headers={"Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "lumtail-site-build"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def sync() -> None:
    """Refresh data/*.json. On API failure keep the previous data and warn, so a
    GitHub outage never blocks a manual page update."""
    try:
        releases = github(f"repos/{REPO}/releases?per_page=30")
        advisories = github(f"repos/{REPO}/security-advisories?state=published&per_page=100")
    except (OSError, ValueError) as error:
        print(f"::warning::GitHub sync failed, keeping data/*.json: {error}")
        return
    DATA.mkdir(exist_ok=True)
    write_json(DATA / "releases.json", [{
        "tag": r["tag_name"],
        "name": r.get("name") or r["tag_name"],
        "published_at": r.get("published_at"),
        "prerelease": r.get("prerelease", False),
        "url": r["html_url"],
        "assets": [{
            "name": a["name"], "size": a["size"],
            "url": a["browser_download_url"],
            "sha256": (a.get("digest") or "").removeprefix("sha256:") or None,
        } for a in r.get("assets", [])],
    } for r in releases if not r.get("draft")])
    write_json(DATA / "advisories.json", [{
        "ghsa": a["ghsa_id"],
        "cve": a.get("cve_id"),
        "summary": a["summary"],
        "severity": a.get("severity") or "unknown",
        "cvss": ((a.get("cvss_severities") or {}).get("cvss_v4") or {}).get("score")
                or (a.get("cvss") or {}).get("score"),
        "published_at": a.get("published_at"),
        "updated_at": a.get("updated_at"),
        "withdrawn_at": a.get("withdrawn_at"),
        "url": a["html_url"],
        "affected": [{
            "range": v.get("vulnerable_version_range"),
            "patched": v.get("patched_versions"),
        } for v in a.get("vulnerabilities") or []],
    } for a in advisories])
    print(f"synced: {len(releases)} releases, {len(advisories)} advisories")


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_json(name: str, default):
    path = DATA / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


# --------------------------------------------------------------------------- helpers

def day(stamp: str | None) -> str:
    if not stamp:
        return ""
    return dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")).strftime("%B %-d, %Y")


def human_size(size: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return ""


# Distribution tags and package formats from lumtail's release workflow.
LINUX_PACKAGES = (
    (r"[.~]debian(\d+)_[^.]+\.deb$", "Debian {}"),
    (r"[.~]ubuntu(\d+\.\d+)_[^.]+\.deb$", "Ubuntu {}"),
    (r"\.fc(\d+)\.[^.]+\.rpm$", "Fedora {}"),
    (r"\.el(\d+)\.[^.]+\.rpm$", "AlmaLinux {}"),
    (r"\.lp(\d{2})(\d+)\.[^.]+\.rpm$", "openSUSE Leap {}.{}"),
    (r"\.amzn(\d+)\.[^.]+\.rpm$", "Amazon Linux {}"),
    (r"\.pkg\.tar\.zst$", "Arch Linux"),
    (r"\.gpkg\.tar$", "Gentoo"),
    (r"-nixos-[^.]+\.tar\.(?:gz|xz)$", "NixOS"),
)


def platform_of(name: str) -> tuple[str, str]:
    low = name.lower()
    if re.search(r"(sha256|sha512|checksums?|\.sig$|\.asc$|\.pem$|\.sbom|\.spdx|\.intoto|\.sigstore)", low):
        return "Checksums & signatures", ""
    system = next((label for key, label in (
        ("linux", "Linux"), ("darwin", "macOS"), ("macos", "macOS"), ("apple", "macOS"),
        ("freebsd", "FreeBSD"), ("openbsd", "OpenBSD"), ("netbsd", "NetBSD"))
        if key in low), "")
    arch = next((label for key, label in (
        ("x86_64", "x86-64"), ("amd64", "x86-64"), ("aarch64", "arm64"),
        ("arm64", "arm64"), ("universal", "universal"))
        if key in low), "")
    for pattern, label in LINUX_PACKAGES:
        if match := re.search(pattern, low):
            return label.format(*match.groups()), arch
    if not system and re.search(r"(source|src|\.tar\.(gz|xz)$)", low):
        system = "Source"
    return system or "Other", arch


# --------------------------------------------------------------------------- demos

def gif_size(path: Path) -> tuple[int, int]:
    header = path.read_bytes()[:10]
    if header[:4] != b"GIF8":
        sys.exit(f"{path}: not a GIF")
    return int.from_bytes(header[6:8], "little"), int.from_bytes(header[8:10], "little")


def cast_info(path: Path) -> tuple[str, list[str]]:
    """Title and the lumtail commands typed in an asciinema v2 recording."""
    lines = path.read_text(encoding="utf-8").splitlines()
    title = json.loads(lines[0]).get("title", "").removeprefix("Lumtail: ")
    text = "".join(event[2] for event in map(json.loads, lines[1:]) if event[1] == "o")
    # Drop escape sequences and the " \r" a terminal emits when a line wraps.
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text).replace(" \r", "").replace("\r", "")
    commands = [line[2:].strip() for line in text.split("\n") if line.startswith("$ lumtail")]
    # Sentence case, but keep names that are always lowercase (nginx, sshd).
    if not re.match(r"(nginx|sshd)\b", title):
        title = title[:1].upper() + title[1:]
    return title, commands


def load_demos(source: Path) -> list[dict]:
    demos = []
    for stem, label in DEMOS:
        base = source / "assets" / "demo"
        title, commands = cast_info(base / f"{stem}.cast")
        if not title or not commands:
            sys.exit(f"{stem}.cast: missing title or lumtail command")
        demos.append({"key": stem, "label": label, "title": title, "commands": commands,
                      "size": gif_size(base / f"{stem}.gif"),
                      "mobile_size": gif_size(base / f"{stem}-mobile.gif")})
    return demos


def demo_shot(d: dict) -> str:
    (w, h), (mw, mh) = d["size"], d["mobile_size"]
    alt = f"Terminal recording: {d['title'].rstrip('.')}. Runs " + "; then ".join(d["commands"]) + "."
    return f"""<picture class="shot shot-demo shot-{d['key']}" hidden>
          <source data-srcset="assets/demo/{d['key']}-mobile.gif" media="(max-width: 640px)" width="{mw}" height="{mh}">
          <img data-src="assets/demo/{d['key']}.gif" width="{w}" height="{h}" alt="{esc(alt)}">
        </picture>"""


# --------------------------------------------------------------------------- benchmarks

# Recorded runs live in lumtail/benchmarks/results/<revision>/. The page shows the
# newest run that has all three files below, and says whether the code changed since.
BENCH_FILES = ("public-logs.json", "stress-1m.json", "suite.json")
CODE_PATHS = ("src", "include", "CMakeLists.txt", "cmake")
PUBLIC_QUERIES = (("parse", "Every record"), ("selective", "Selective filter"),
                  ("broad", "Broad filter"), ("late-miss", "Filter with no match"))
GENERATED = (("json", "JSON Lines"), ("json-ts", "JSON with epoch times, every other record 64 extra fields"),
             ("kubernetes", "Kubernetes audit"), ("zeek", "Zeek JSON"), ("access", "Web access log"),
             ("syslog", "syslog"), ("plain", "Plain text"), ("mixed", "JSON, syslog, access and plain"),
             ("multiline", "Multiline, three lines per record"), ("long", "JSON, 4 KiB messages"))
MIB = 2 ** 20
# Public datasets left off the site, by corpus key in public-logs.json.
# "access" is the Zanbil web access log.
EXCLUDED_DATASETS = frozenset({"access"})


def git(source: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(source), *args], capture_output=True, text=True).stdout.strip()


def load_benchmarks(source: Path) -> dict | None:
    root = source / "benchmarks" / "results"
    runs = [d for d in root.iterdir() if d.is_dir() and all((d / f).exists() for f in BENCH_FILES)] \
        if root.is_dir() else []
    if not runs:
        return None
    # Newest by the recorded finish time, so a shallow checkout works too.
    stamp = lambda d: (lambda p: p.get("finished_utc") or p.get("created_utc") or "")(
        json.loads((d / "public-logs.json").read_text(encoding="utf-8")))
    run = max(runs, key=stamp)
    public, stress, suite = (json.loads((run / f).read_text(encoding="utf-8")) for f in BENCH_FILES)
    revision = public["host"]["revision"]
    report = (run / "README.md").read_text(encoding="utf-8") if (run / "README.md").exists() else ""
    compiler = re.search(r"^- Compiler: ([^,\n]+)", report, re.M)
    host = public["host"]
    platform = re.match(r"macOS-([\d.]+)", host["platform"])

    def peak(row) -> float:
        return row["peak_rss_bytes"]["max"] / MIB

    datasets = []
    for key, corpus in public["corpora"].items():
        if key in EXCLUDED_DATASETS:
            continue
        rows = {(r["query"], r["threads"]): r for r in public["results"]
                if r["corpus"] == key and r["mode"] == "json"}
        queries = []
        for name, label in PUBLIC_QUERIES:
            one, auto = rows.get((name, "1")), rows.get((name, "auto"))
            if not (one and auto):
                continue
            queries.append({"label": label, "matches": auto["matches"],
                            "one": one["input_mib_per_second"], "auto": auto["input_mib_per_second"],
                            "seconds": auto["seconds"]["median"], "peak": max(peak(one), peak(auto))})
        src = corpus["source"]
        datasets.append({"title": src["title"], "page": src["page"], "license": src["license"],
                         "credit": src["credit"], "origin": src.get("origin", ""),
                         "gib": corpus["input_bytes"] / 2 ** 30, "records": corpus["input_records"],
                         "passes": corpus["passes"], "source_mib": corpus["source_bytes"] / MIB,
                         "queries": queries})

    cases = {(r["corpus"], r["mode"], r["threads"]): r for r in stress["results"] if r.get("suite") == "pipeline"}
    generated = []
    for key, label in GENERATED:
        cells = {(m, t): cases.get((key, m, t)) for m in ("text", "json", "raw") for t in ("1", "auto")}
        if not all(cells.values()):
            continue
        generated.append({"key": key, "label": label, "mib": stress["corpora"][key]["bytes"] / MIB,
                          **{f"{m}_{t}": cells[(m, t)]["input_mib_per_second"] for m, t in cells},
                          "records": cells[("text", "auto")]["records_per_second"],
                          "peak": max(peak(r) for r in cells.values())})

    by_case = {r["case"]: r for r in suite["results"]}
    ms = lambda case, key="seconds": by_case[case][key]["median"] * 1000 if case in by_case else None
    response = [("Start-up and exit, <code>--version</code>", ms("startup/version")),
                ("First record through a pipe", ms("latency/pipe/line/1", "first_response_seconds")),
                ("Each later record through a pipe", ms("latency/pipe/line/1", "response_seconds")),
                ("First record appended to a followed file", ms("latency/follow/line/1", "first_response_seconds")),
                ("Each later record appended to a followed file", ms("latency/follow/line/1", "response_seconds"))]

    # Needs the revision in the local history; without it the page says it could not tell.
    known = git(source, "cat-file", "-t", revision) == "commit"
    changes = git(source, "rev-list", "--count", f"{revision}..HEAD", "--", *CODE_PATHS) if known else ""
    return {
        "revision": revision, "dir": run.name,
        "date": public.get("finished_utc") or public["created_utc"],
        "committed": git(source, "show", "-s", "--format=%cI", revision),
        "code_changes": int(changes) if changes.isdigit() else None,
        "cpu": host.get("cpu") or host.get("machine", ""), "cpus": host.get("logical_cpus"),
        "os": f"macOS {platform[1]}" if platform else host["platform"],
        "compiler": compiler[1].strip() if compiler else "",
        "repetitions": public["settings"]["repetitions"], "warmups": public["settings"]["warmups"],
        "datasets": datasets, "generated": generated,
        "response": [(label, value) for label, value in response if value is not None],
        "files": [run / f for f in BENCH_FILES] + ([run / "README.md"] if report else []),
    }


# --------------------------------------------------------------------------- manual rendering

def normalize(raw: str) -> tuple[str, str]:
    """Give every mandoc version the same markup.

    mandoc 1.14.6 (Debian, Ubuntu) emits <h1 class="Sh">, <h2 class="Ss"> and
    head/foot tables; newer releases emit <h2>/<h3> and head/foot divs.
    The site draws its own header and footer, so both forms are dropped.
    """
    date = re.search(r'class="foot-date">(.*?)</(?:span|td)>', raw, re.S)
    raw = re.sub(r'<(div|table) class="(?:head|foot)"[^>]*>.*?</\1>\s*', "", raw, flags=re.S)
    raw = re.sub(r"</?main[^>]*>", "", raw)
    raw = re.sub(r'^<div class="manual-text">\s*(.*)</div>\s*$', r"\1", raw.strip(), flags=re.S)
    if '<h1 class="Sh"' in raw:
        raw = re.sub(r'<h2 class="Ss"(.*?)</h2>', r'<h3 class="Ss"\1</h3>', raw, flags=re.S)
        raw = re.sub(r'<h1 class="Sh"(.*?)</h1>', r'<h2 class="Sh"\1</h2>', raw, flags=re.S)
    return raw, " ".join(date[1].split()) if date else ""


def check_manual(m: dict) -> list[str]:
    problems = []
    if sum(1 for level, *_ in m["toc"] if level == 2) < 3:
        problems.append("fewer than 3 sections in the contents")
    if re.search(r'class="(head|foot)[-"]', m["body"]) or "<h1" in m["body"]:
        problems.append("unnormalized mandoc markup")
    if not m["summary"] or not m["date"]:
        problems.append("missing NAME description or date")
    return [f'{m["page"]}: {p}' for p in problems]


def render_manual(source: Path, page: str) -> dict:
    name, sec = page.rsplit(".", 1)
    raw = subprocess.run(
        ["mandoc", "-Thtml", "-I", "os=lumtail", "-O", "fragment,man=%N.%S.html",
         str(source / "man" / page)],
        check=True, capture_output=True, text=True).stdout

    raw, date = normalize(raw)

    def xr(match: re.Match) -> str:
        target, tsec = match[1], match[2]
        if f"{target}.{tsec}" in PAGES:
            return f'href="{target}.{tsec}.html"'
        return f'href="{EXTERNAL_MAN.format(name=target, sec=tsec)}" rel="external"'
    raw = re.sub(r'href="([A-Za-z0-9_.+-]+)\.([0-9][a-z]*)\.html"', xr, raw)

    toc = []
    for level, ident, text in re.findall(
            r'<h([23]) class="S[hs]" id="([^"]+)"><a[^>]*>(.*?)</a></h[23]>', raw, re.S):
        label = " ".join(re.sub(r"<[^>]+>", "", text).split())
        toc.append((int(level), ident, html.unescape(label)))

    nd = re.search(r'<span class="Nd"[^>]*>(.*?)</span>', raw, re.S)
    summary = " ".join(html.unescape(re.sub(r"<[^>]+>", "", nd[1])).split()) if nd else ""
    markdown = subprocess.run(
        ["mandoc", "-Tmarkdown", "-I", "os=lumtail", str(source / "man" / page)],
        check=True, capture_output=True, text=True).stdout
    return {"page": page, "name": name, "sec": sec, "body": raw.strip(), "toc": toc,
            "summary": summary, "markdown": markdown.replace("&nbsp;", " ").strip() + "\n",
            "date": date,
            "ids": set(re.findall(r'id="([^"]+)"', raw))}


# --------------------------------------------------------------------------- layout

def mark(root: str, cls: str = "mark") -> str:
    return (f'<picture class="{cls}">'
            f'<source srcset="{root}assets/img/lumtail-mark-dark.svg" media="(prefers-color-scheme: dark)">'
            f'<img src="{root}assets/img/lumtail-mark-light.svg" alt="" width="32" height="32"></picture>')


def layout(*, root: str, path: str, title: str, description: str, body: str,
           section: str, ctx: dict, extra_head: str = "") -> str:
    links = [("man", "man/", "Manual"), ("install", "download/", "Install")]
    if ctx["advisories"]:
        links.append(("security", "security/", "Security"))
    nav = "".join(f'<a href="{root}{href}"{CURRENT if key == section else ""}>{label}</a>'
                  for key, href, label in links)
    feeds = "".join(
        f'<link rel="alternate" type="application/atom+xml" title="{label}" href="{root}{href}">\n'
        for present, label, href in ((ctx["releases"], "Lumtail releases", "download/releases.xml"),
                                     (ctx["advisories"], "Lumtail security advisories", "security/advisories.xml"))
        if present)
    canonical = BASE_URL + path.removesuffix("index.html")
    return f"""<!doctype html>
{SPDX}<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<meta name="description" content="{esc(description)}">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#F8F7F4" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#1D1F1E" media="(prefers-color-scheme: dark)">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="strict-origin-when-cross-origin">
<link rel="canonical" href="{canonical}">
<link rel="icon" href="{root}favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="{root}assets/img/lumtail-avatar.png">
<link rel="stylesheet" href="{root}assets/site.css">
{feeds}<meta property="og:type" content="website">
<meta property="og:site_name" content="Lumtail">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(description)}">
<meta property="og:url" content="{canonical}">
<meta property="og:image" content="{BASE_URL}assets/img/lumtail-social.png">
<meta property="og:image:width" content="1280">
<meta property="og:image:height" content="640">
<meta property="og:image:alt" content="Lumtail. Live. Unified. Monitoring and tailing.">
<meta name="twitter:card" content="summary_large_image">
{extra_head}<script src="{root}assets/site.js" defer></script>
</head>
<body class="s-{section}">
<a class="skip" href="#content">Skip to content</a>
<header class="top">
  <div class="wrap top-inner">
    <a class="brand" href="{root}" aria-label="Lumtail home">{mark(root)}<span>Lumtail</span></a>
    <nav class="nav" aria-label="Site">{nav}<a href="{GH}" rel="external">GitHub</a></nav>
  </div>
</header>
<main id="content">
{body}
</main>
<footer class="site-foot">
  <div class="wrap foot-inner">
    <span class="foot-mark">{mark(root)}</span>
    <nav class="foot-links" aria-label="Project">
      <a href="{GH}/blob/main/docs/guide.md">Guide</a>
      <a href="{GH}/issues/new?template=bug_report.yml">Report a bug</a>
      <a href="{root}security/">Security</a>
      {f'<a href="{root}performance/">Performance</a>' if ctx.get("bench") else ""}
      <a href="{root}license/">MIT License</a>
      <a href="{root}llms.txt">llms.txt</a>
    </nav>
    <p class="legal">Third-party terms: <a href="{GH}/blob/main/THIRD_PARTY_NOTICES.md">notices</a>.
      Built from <a href="{GH}/tree/{ctx['commit']}"><code>{ctx['commit'][:7]}</code></a>.</p>
  </div>
</footer>
</body>
</html>
"""


def copy_block(command: str) -> str:
    return (f'<div class="cmd"><pre><code><span class="ps" aria-hidden="true">$ </span>{esc(command)}</code></pre>'
            f'<button type="button" class="copy" data-copy="{esc(command)}" aria-label="Copy command">Copy</button></div>')


def manual_list(ctx: dict, prefix: str) -> str:
    rows = "".join(f"""<li><a href="{prefix}{m['page']}.html">
      <span class="ml-ref">{m['name']}<span class="sec">({m['sec']})</span></span>
      <span class="ml-desc">{esc(m['summary'])}</span></a></li>""" for m in ctx["manuals"])
    return f'<ul class="manlist">{rows}</ul>'


BUILD_STEPS = (f"git clone {GH}.git && cd lumtail",
               "cmake -S . -B build -DCMAKE_BUILD_TYPE=Release",
               "cmake --build build --parallel")


# --------------------------------------------------------------------------- pages

def page_index(ctx: dict) -> str:
    latest = next((r for r in ctx["releases"] if not r["prerelease"]), None)
    version = f'<a class="version" href="download/">{esc(latest["tag"])}</a>' if latest else ""
    body = f"""<section class="home">
  <div class="wrap home-inner">
    {version}
    <h1>Live. Unified. <span>Monitoring and tailing.</span></h1>
    <p class="lede">Lumtail follows logs as they grow, reads each record in its own format
      and shows them as one stream you can filter.</p>
    <figure class="stage" data-mode="output">
      <div class="frame">
        <picture class="shot shot-output">
          <source srcset="assets/img/lumtail-preview-mobile-dark.svg" media="(max-width: 640px) and (prefers-color-scheme: dark)">
          <source srcset="assets/img/lumtail-preview-mobile-light.svg" media="(max-width: 640px)">
          <source srcset="assets/img/lumtail-preview-dark.svg" media="(prefers-color-scheme: dark)">
          <img src="assets/img/lumtail-preview-light.svg" width="1120" height="420"
               alt="lumtail --rules examples/modules.json examples/mixed.log shows JSON Lines, syslog, access log and custom records as one stream with colored severity labels.">
        </picture>
        {"".join(demo_shot(d) for d in ctx["demos"])}
      </div>
      <figcaption>
        <span class="caption caption-output">Four formats in one file, one stream.</span>
        {"".join(f'<span class="caption caption-{d["key"]}" hidden>{esc(d["title"])}.</span>' for d in ctx["demos"])}
        <span class="switch" role="group" aria-label="Preview" hidden>
          <button type="button" data-show="output" aria-pressed="true">Output</button>
          {"".join(f'<button type="button" data-show="{d["key"]}" aria-pressed="false">{esc(d["label"])}</button>' for d in ctx["demos"])}
        </span>
      </figcaption>
    </figure>
    <div class="home-actions">
      <div class="cmd cmd-pill"><pre><code><span class="ps" aria-hidden="true">$ </span>lumtail --follow app.log</code></pre><button type="button" class="copy" data-copy="lumtail --follow app.log" aria-label="Copy command">Copy</button></div>
      <a class="btn btn-primary" href="man/lumtail.1.html">Read the manual</a>
      <a class="quiet" href="download/">Install →</a>
    </div>
    <p class="home-agents">Scripts and agents: <code>lumtail --agent</code> writes bounded JSON Lines.
      See <a href="man/lumtail-agent.7.html">lumtail-agent(7)</a> or <a href="llms.txt">llms.txt</a>.</p>
  </div>
</section>
"""
    return layout(root="", path="index.html", title="Lumtail — live unified monitoring and tailing",
                  description="Lumtail follows log files and streams as they grow, reads each record in its own format and shows them as one stream you can filter.",
                  body=body, section="home", ctx=ctx, extra_head=json_ld(ctx))


def json_ld(ctx: dict) -> str:
    data = {
        "@context": "https://schema.org", "@type": "SoftwareApplication",
        "name": "Lumtail", "url": BASE_URL, "applicationCategory": "DeveloperApplication",
        "operatingSystem": "Linux, macOS, FreeBSD, OpenBSD, NetBSD",
        "description": "Follows log files and streams as they grow, reads each record in its own format "
                       "and shows them as one stream you can filter.",
        "license": "https://spdx.org/licenses/MIT.html", "codeRepository": GH,
        "image": f"{BASE_URL}assets/img/lumtail-social.png",
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
        "installUrl": f"{BASE_URL}download/",
        "softwareHelp": [{"@type": "TechArticle", "name": f"{m['name']}({m['sec']})",
                          "description": m["summary"], "url": f"{BASE_URL}man/{m['page']}.html",
                          "encoding": {"@type": "MediaObject", "encodingFormat": "text/markdown",
                                       "contentUrl": f"{BASE_URL}man/{m['page']}.md"}}
                         for m in ctx["manuals"]],
    }
    latest = next((r for r in ctx["releases"] if not r["prerelease"]), None)
    if latest:
        data["softwareVersion"] = latest["tag"].removeprefix("v")
        data["downloadUrl"] = f"{BASE_URL}download/"
    return f'<script type="application/ld+json">{json.dumps(data, separators=(",", ":"))}</script>\n'


def page_manual(ctx: dict, m: dict) -> str:
    root = "../"
    switch = "".join(
        f'<a href="{o["page"]}.html"{CURRENT if o is m else ""}>'
        f'{o["name"]}<span class="sec">({o["sec"]})</span></a>' for o in ctx["manuals"])
    items, open_sub = [], False
    for level, ident, label in m["toc"]:
        if level == 2:
            if open_sub:
                items.append("</ol></li>")
                open_sub = False
            elif items:
                items.append("</li>")
            items.append(f'<li><a href="#{ident}">{esc(label.title() if label.isupper() else label)}</a>')
        else:
            if not open_sub:
                items.append("<ol>")
                open_sub = True
            items.append(f'<li><a href="#{ident}">{esc(label)}</a></li>')
    items.append("</ol></li>" if open_sub else "</li>")
    toc = "".join(items)
    ref = f'{m["name"].upper()}({m["sec"]})'
    source = f'{GH}/blob/{ctx["commit"]}/man/{m["page"]}'
    body = f"""<div class="wrap man-layout">
  <aside class="man-side" aria-label="Manual navigation">
    <nav class="man-switch" aria-label="Manual pages">{switch}</nav>
    <details class="toc" open>
      <summary>On this page</summary>
      <ol>{toc}</ol>
    </details>
  </aside>
  <article class="man">
    <h1 class="vh">{m['name']}({m['sec']}) — {esc(m['summary'])}</h1>
    <div class="man-head" aria-hidden="true">
      <span>{ref}</span><span class="vol">{SECTION_NAMES[m['sec']]} Manual</span><span>{ref}</span>
    </div>
    <div class="man-terminal"><div class="term">{copy_block(f"man {m['sec']} {m['name']}" if m['sec'] != '1' else f"man {m['name']}")}</div></div>
    <div class="manual-text">
{m['body']}
    </div>
    <div class="man-foot" aria-hidden="true">
      <span>Lumtail</span><span>{esc(m['date'])}</span><span>{ref}</span>
    </div>
    <p class="man-edit"><a href="{source}">Source</a>
      <a href="{m['page']}.md" type="text/markdown">Markdown</a>
      <a href="{GH}/issues/new?template=bug_report.yml&amp;title={esc(m['name'])}({m['sec']})%3A%20">Report a problem</a></p>
  </article>
</div>
"""
    return layout(root=root, path=f"man/{m['page']}.html",
                  title=f"{m['name']}({m['sec']}) — {m['summary']}",
                  description=f"{m['name']}({m['sec']}): {m['summary']}. Lumtail manual page.",
                  body=body, section="man", ctx=ctx,
                  extra_head=f'<link rel="alternate" type="text/markdown" href="{m["page"]}.md">\n')


def page_man_index(ctx: dict) -> str:
    body = f"""<section class="page-head"><div class="wrap narrow">
  <h1>Manual</h1>
  <p class="lede">Every option, format and rule. Installed copies carry the same pages.</p>
  {manual_list(ctx, "")}
</div></section>
"""
    return layout(root="../", path="man/index.html", title="Lumtail manual",
                  description="Lumtail manual pages: lumtail(1), lumtail-rules(5), lumtail-formats(7) and lumtail-agent(7).",
                  body=body, section="man", ctx=ctx)


def asset_table(release: dict) -> str:
    if not release["assets"]:
        return '<p class="empty-inline">No binaries attached; use the source archive on GitHub.</p>'
    rows = []
    # Put the generic Linux archives first, followed by named distributions.
    order = {"Linux": 0, "macOS": 2, "FreeBSD": 3, "OpenBSD": 4, "NetBSD": 5,
             "Source": 6, "Other": 7, "Checksums & signatures": 8}
    assets = [(*platform_of(a["name"]), a) for a in release["assets"]]
    for system, arch, a in sorted(assets, key=lambda row: (order.get(row[0], 1), row[0], row[2]["name"])):
        digest = (f'<button type="button" class="hash copy" data-copy="{a["sha256"]}" title="Copy SHA-256">'
                  f'<code>{a["sha256"][:12]}…</code></button>' if a.get("sha256") else '<span class="muted">—</span>')
        rows.append(f"""<tr><td><span class="os">{esc(system)}</span>{f' <span class="arch">{esc(arch)}</span>' if arch else ''}</td>
          <td><a href="{esc(a['url'])}" download><code>{esc(a['name'])}</code></a></td>
          <td class="num">{human_size(a['size'])}</td><td>{digest}</td></tr>""")
    return f"""<div class="table-wrap"><table class="assets">
      <thead><tr><th>Platform</th><th>File</th><th class="num">Size</th><th>SHA-256</th></tr></thead>
      <tbody>{"".join(rows)}</tbody></table></div>"""


def page_download(ctx: dict) -> str:
    releases = ctx["releases"]
    latest = next((r for r in releases if not r["prerelease"]), releases[0] if releases else None)
    source = f"""<h2 id="source">From source</h2>
  <p class="sub">CMake 3.24+ and a C++23 compiler with <code>&lt;expected&gt;</code>.
    Linux, macOS, FreeBSD, OpenBSD and NetBSD.</p>
  <div class="term">{"".join(copy_block(c) for c in BUILD_STEPS)}</div>
  <p class="note">The executable is <code>build/lumtail</code>. Without network access, follow the
    <a href="{GH}/blob/main/docs/guide.md#offline-builds">offline build</a>.</p>"""
    if not latest:
        body = f"""<section class="page-head"><div class="wrap narrow">
  <h1>Install</h1>
  <p class="lede">Build from source in three commands. Prebuilt binaries will appear here with each release.</p>
</div></section>
<section class="band band-tight"><div class="wrap narrow">{source}</div></section>
"""
    else:
        pre = ' <span class="badge badge-medium">Pre-release</span>' if latest["prerelease"] else ""
        older = "".join(f"""<details class="release">
      <summary><span>{esc(r['name'])}</span>{' <span class="badge badge-medium">Pre-release</span>' if r['prerelease'] else ''}
        <span class="muted">{day(r['published_at'])}</span></summary>
      <p><a href="{esc(r['url'])}">Release notes</a></p>{asset_table(r)}</details>"""
                        for r in releases if r is not latest)
        body = f"""<section class="page-head"><div class="wrap">
  <h1>Install</h1>
  <p class="lede">{esc(latest['name'])}{pre} · {day(latest['published_at'])} ·
    <a href="{esc(latest['url'])}">Release notes</a></p>
</div></section>
<section class="band band-tight"><div class="wrap">
  {asset_table(latest)}
  <p class="note">Check a download with <code>shasum -a 256 <var>file</var></code> against the digest above; click a digest to copy it.
    New versions: <a href="releases.xml">release feed</a>.</p>
  {f'<h2 class="gap">Earlier releases</h2>{older}' if older else ''}
  <div class="narrow-left gap">{source}</div>
  <p class="note">Redistributing a binary? Ship <code>LICENSE</code>, <code>THIRD_PARTY_NOTICES.md</code> and
    <code>LICENSES/</code> with it (<a href="{GH}/blob/main/docs/licenses.md">packaging licenses</a>).</p>
</div></section>
"""
    return layout(root="../", path="download/index.html", title="Install Lumtail",
                  description="Install Lumtail on Linux, macOS, FreeBSD, OpenBSD and NetBSD.",
                  body=body, section="install", ctx=ctx)


def page_security(ctx: dict) -> str:
    advisories = sorted(ctx["advisories"], key=lambda a: a.get("published_at") or "", reverse=True)
    items = []
    for a in advisories:
        sev = a["severity"].lower()
        withdrawn = ' <span class="badge">Withdrawn</span>' if a.get("withdrawn_at") else ""
        affected = "".join(
            f'<li><span class="muted">Affected</span> <code>{esc(x["range"] or "—")}</code>'
            f' <span class="muted">Patched</span> <code>{esc(x["patched"] or "none yet")}</code></li>'
            for x in a["affected"])
        ids = f'<code>{esc(a["ghsa"])}</code>' + (f' · <code>{esc(a["cve"])}</code>' if a.get("cve") else "")
        items.append(f"""<article class="advisory{' is-withdrawn' if withdrawn else ''}" id="{esc(a['ghsa'])}">
      <div class="advisory-head"><span class="badge badge-{sev}">{esc(sev.title())}{f" · {a['cvss']}" if a.get('cvss') else ""}</span>{withdrawn}
        <span class="muted">{day(a['published_at'])}</span></div>
      <h2><a href="{esc(a['url'])}">{esc(a['summary'])}</a></h2>
      <p class="ids">{ids}</p>
      {f'<ul class="affected">{affected}</ul>' if affected else ''}
    </article>""")
    listing = ("".join(items) + '<p class="note">Subscribe: <a href="advisories.xml">advisory feed</a>.</p>'
               if items else '<p class="sub">No advisories have been published.</p>')
    body = f"""<section class="page-head"><div class="wrap narrow">
  <h1>Security</h1>
  <p class="lede">Found a vulnerability? Report it privately on GitHub. Only you and the maintainers
    see the report until a fix is out.</p>
  <p class="hero-links"><a class="btn btn-primary" href="{GH}/security/advisories/new">Report privately</a></p>
  <p class="note">Include <code>lumtail --version</code>, <code>lumtail --sandbox-status</code>, the platform
    and a short log that reproduces it. Hardening notes are in
    <a href="../man/lumtail.1.html#SECURITY_CONSIDERATIONS">lumtail(1)</a>.</p>
</div></section>
<section class="band band-tight"><div class="wrap narrow">
  <h2>Advisories</h2>
  {listing}
</div></section>
"""
    return layout(root="../", path="security/index.html", title="Lumtail security",
                  description="How to report a Lumtail vulnerability privately, and published advisories.",
                  body=body, section="security", ctx=ctx)


def num(value: float, digits: int = 0) -> str:
    return f"{value:,.{digits}f}"


def millis(value: float) -> str:
    return num(value, 3 if value < 1 else 1 if value < 10 else 0)


def bench_status(b: dict) -> str:
    if b["code_changes"] == 0:
        return "The code on <code>main</code> has not changed since, so these numbers describe it."
    if b["code_changes"]:
        n = b["code_changes"]
        return (f"{n} later commit{'s' if n != 1 else ''} on <code>main</code> change{'' if n != 1 else 's'} the code; "
                "these numbers may no longer describe it.")
    return "This build could not check whether the code changed since."


def bench_summary(b: dict) -> dict:
    """Machine-readable digest of the page, for scripts and agents."""
    return {
        "license": "MIT", "copyright": "2026 lumtail contributors",
        "revision": b["revision"], "committed": b["committed"], "measured": b["date"],
        "code_changes_since": b["code_changes"],
        "host": {"cpu": b["cpu"], "logical_cpus": b["cpus"], "os": b["os"], "compiler": b["compiler"]},
        "method": {"statistic": "median", "repetitions": b["repetitions"], "warmups": b["warmups"],
                   "cache": "warm", "output": "/dev/null", "startup": "included",
                   "throughput": "input MiB divided by elapsed seconds", "peak_memory": "largest peak RSS of any run"},
        "public_logs": [{"dataset": d["title"], "license": d["license"], "source": d["page"],
                         "input_gib": round(d["gib"], 2), "records": d["records"],
                         "queries": [{"query": q["label"], "matching_records": q["matches"],
                                      "mib_per_second_1_worker": round(q["one"]),
                                      "mib_per_second_auto": round(q["auto"]),
                                      "seconds_auto": round(q["seconds"], 3),
                                      "peak_memory_mib": round(q["peak"], 1)} for q in d["queries"]]}
                        for d in b["datasets"]],
        "generated_1m_records": [{"corpus": g["key"], "description": g["label"], "input_mib": round(g["mib"]),
                                  **{f"{m}_mib_per_second_{t}": round(g[f"{m}_{t}"])
                                     for m in ("text", "json", "raw") for t in ("1", "auto")},
                                  "text_records_per_second_auto": round(g["records"]),
                                  "peak_memory_mib": round(g["peak"], 1)} for g in b["generated"]],
        "response_ms": [{"measurement": re.sub(r"<[^>]+>", "", label), "median_ms": round(value, 3)}
                        for label, value in b["response"]],
        "raw_results": f"{GH}/tree/main/benchmarks/results/{b['dir']}",
    }


def page_performance(ctx: dict) -> str:
    b = ctx["bench"]
    rev = b["revision"]
    results = f"{GH}/tree/main/benchmarks/results/{b['dir']}"
    when = day(b["date"])
    host = ", ".join(filter(None, (b["cpu"], f"{b['cpus']} logical CPUs" if b["cpus"] else "", b["os"])))
    def th(*cols: str, text_cols: int = 1) -> str:
        return "".join(f'<th scope="col"{" class=num" if i >= text_cols else ""}>{c}</th>' for i, c in enumerate(cols))

    public_rows = []
    for d in b["datasets"]:
        for i, q in enumerate(d["queries"]):
            head = (f'<th scope="row" rowspan="{len(d["queries"])}">{esc(d["title"])}'
                    f'<span class="cell-note">{num(d["gib"], 2)} GiB · {num(d["records"])} records</span></th>') if i == 0 else ""
            public_rows.append(f"""<tr>{head}<td>{esc(q['label'])}</td><td class="num">{num(q['matches'])}</td>
          <td class="num">{num(q['one'])}</td><td class="num">{num(q['auto'])}</td>
          <td class="num">{num(q['seconds'], 2)}</td><td class="num">{num(q['peak'], 1)}</td></tr>""")
    sources = "".join(f"""<li><a href="{esc(d['page'])}">{esc(d['title'])}</a> ({esc(d['license'])}).
        {esc(d['origin'].rstrip('.'))}.{f" Built from a {num(d['source_mib'], 1)} MiB source repeated {d['passes']} times." if d['passes'] > 1 else ''}
        <span class="muted">Credit: {esc(d['credit'])}.</span></li>""" for d in b["datasets"])

    gen_rows = "".join(f"""<tr><th scope="row">{esc(g['label'])}<span class="cell-note"><code>{esc(g['key'])}</code></span></th>
          <td class="num">{num(g['mib'])}</td><td class="num">{num(g['text_1'])}</td><td class="num">{num(g['text_auto'])}</td>
          <td class="num">{num(g['json_auto'])}</td><td class="num">{num(g['raw_auto'])}</td>
          <td class="num">{num(g['records'] / 1e6, 1)}</td><td class="num">{num(g['peak'], 1)}</td></tr>"""
                       for g in b["generated"])
    resp_rows = "".join(f'<tr><th scope="row">{label}</th><td class="num">{millis(value)}</td></tr>'
                        for label, value in b["response"])
    peak_all = max([q["peak"] for d in b["datasets"] for q in d["queries"]] + [g["peak"] for g in b["generated"]])

    body = f"""<section class="page-head"><div class="wrap">
  <h1>Performance</h1>
  <p class="lede">How fast Lumtail reads, filters and writes logs, and how much memory it uses,
    measured on one machine.</p>
  <p class="note">Revision <a href="{GH}/commit/{rev}"><code>{rev[:7]}</code></a>, measured {when}. {bench_status(b)}</p>
</div></section>
<section class="band band-tight"><div class="wrap">
  <h2 id="method">How to read these numbers</h2>
  <dl class="facts">
    <dt>Machine</dt><dd>{esc(host)}{f"; {esc(b['compiler'])}, release build" if b['compiler'] else ""}.</dd>
    <dt>Statistic</dt><dd>Median of {b['repetitions']} runs after {b['warmups']} warm-up run. Files are in the page cache,
      output goes to <code>/dev/null</code>, and process start-up is included.</dd>
    <dt>Throughput</dt><dd>Input size in MiB divided by elapsed seconds.</dd>
    <dt>Workers</dt><dd><code>1</code> runs one worker thread; <code>auto</code> lets Lumtail choose
      (<a href="../man/lumtail.1.html#Workers_and_statistics"><code>--threads</code></a>), here up to the {b['cpus']} logical CPUs.</dd>
    <dt>Memory</dt><dd>Largest peak resident set size of any run. No case exceeded {num(peak_all, 1)} MiB.</dd>
    <dt>Limits</dt><dd>One machine and one run. Another CPU, a cold cache, a slow disk or a terminal as output
      changes every number. Treat them as orders of magnitude, not guarantees.</dd>
  </dl>

  <h2 id="public-logs" class="gap">Public datasets</h2>
  <p class="sub">{("No", "One", "Two", "Three", "Four", "Five")[min(len(b["datasets"]), 5)]} published log datasets, filtered with fixed queries and written as JSON
    (<code>--output=json</code>). The filter with no match tests 24 patterns against every record.</p>
  <div class="table-wrap"><table class="assets data">
    <thead><tr>{th("Dataset", "Query", "Matching records", "1 worker MiB/s", "auto MiB/s", "auto seconds", "Peak MiB", text_cols=2)}</tr></thead>
    <tbody>{"".join(public_rows)}</tbody></table></div>
  <ul class="sources">{sources}</ul>

  <h2 id="generated" class="gap">One million generated records</h2>
  <p class="sub">Ten generated inputs of 1,000,000 records each. <code>text</code> is the terminal format,
    <code>json</code> writes every parsed field, <code>raw</code> writes the original record unchanged.
    Peak MiB is the largest of the row's runs.</p>
  <div class="table-wrap"><table class="assets data">
    <thead><tr>{th("Input", "MiB", "text 1 worker MiB/s", "text auto MiB/s", "json auto MiB/s", "raw auto MiB/s", "text auto million records/s", "Peak MiB")}</tr></thead>
    <tbody>{gen_rows}</tbody></table></div>

  <h2 id="response" class="gap">Start-up and response time</h2>
  <p class="sub">One worker, one record per line, read back as JSON. A followed file is checked every
    100 ms, which sets the time for later appended records.</p>
  <div class="table-wrap"><table class="assets data narrow-table">
    <thead><tr>{th("Measurement", "Median ms")}</tr></thead>
    <tbody>{resp_rows}</tbody></table></div>

  <p class="note gap">Every sample, command, input hash and executable hash:
    <a href="{results}">benchmark results for <code>{rev[:7]}</code></a>, with the
    <a href="{GH}/blob/main/benchmarks/README.md">benchmark procedure</a>. The figures on this page are also
    available as <a href="summary.json">JSON</a>.</p>
</div></section>
"""
    return layout(root="../", path="performance/index.html", title="Lumtail performance",
                  description=f"Measured throughput, memory and response time of Lumtail at revision {rev[:7]}.",
                  body=body, section="performance", ctx=ctx,
                  extra_head='<link rel="alternate" type="application/json" href="summary.json">\n')


def page_license(ctx: dict) -> str:
    paragraphs = [" ".join(p.split()) for p in ctx["license"].strip().split("\n\n")]
    title, copyright_line, *terms = paragraphs
    body_paras = "".join(
        f'<p class="{"shout" if p.isupper() or p.startswith("THE SOFTWARE") else ""}">{esc(p)}</p>' for p in terms)
    body = f"""<section class="page-head"><div class="wrap narrow">
  <h1>{esc(title)}</h1>
  <p class="lede">{esc(copyright_line)}</p>
  <p class="note">From <a href="{GH}/blob/main/LICENSE"><code>LICENSE</code></a> in the repository.
    Third-party components keep their own terms (<a href="{GH}/blob/main/THIRD_PARTY_NOTICES.md">notices</a>).</p>
  <div class="license">{body_paras}</div>
</div></section>
"""
    return layout(root="../", path="license/index.html", title="Lumtail — MIT License",
                  description="Lumtail is released under the MIT License.",
                  body=body, section="license", ctx=ctx)


def page_404(ctx: dict) -> str:
    body = f"""<section class="page-head page-404"><div class="wrap">
  <p class="code-404">404</p>
  <h1>No record matched.</h1>
  <p class="lede">This page does not exist. Try the <a href="/man/">manual</a> or the <a href="/">home page</a>.</p>
</div></section>"""
    # 404 is served at arbitrary depth, so it uses absolute paths.
    return layout(root="/", path="404.html", title="Not found — Lumtail",
                  description="Page not found.", body=body, section="none", ctx=ctx)


# --------------------------------------------------------------------------- plain text for agents

def strip_spdx(text: str) -> str:
    return re.sub(r"\A\s*<!--.*?-->\s*", "", text, flags=re.S)


def absolute_links(markdown: str, base: str) -> str:
    """Point relative Markdown links at the repository, so they work off GitHub."""
    def fix(match: re.Match) -> str:
        target = match[1]
        if re.match(r"[a-z][a-z0-9+.-]*:|#", target):
            return match[0]
        return f"]({urllib.parse.urljoin(base, target)})"
    return re.sub(r"\]\(([^)\s]+)\)", fix, markdown)


def llms_txt(ctx: dict) -> str:
    """Index for language-model agents, following https://llmstxt.org/."""
    examples = "\n".join(f"    {c}" for c in AGENT_EXAMPLES)
    build_steps = "\n".join(f"    {c}" for c in BUILD_STEPS)
    manuals = "\n".join(f"- [{m['name']}({m['sec']})]({BASE_URL}man/{m['page']}.md): {m['summary']}"
                        for m in ctx["manuals"])
    docs = "\n".join(f"- [{title}]({BASE_URL}docs/{name}): {note}"
                     for name, title, note, _ in ctx["docs"])
    contracts = "\n".join(f"- [{name}]({BASE_URL}cli/v1/{name})" for name in CONTRACTS if name.endswith(".json"))
    latest = next((r for r in ctx["releases"] if not r["prerelease"]), None)
    version = f"The latest release is {latest['tag']}. " if latest else ""
    bench = ctx.get("bench")
    performance = (f"- [Performance]({BASE_URL}performance/): throughput, memory and response time measured at "
                   f"revision {bench['revision'][:7]}; [as JSON]({BASE_URL}performance/summary.json)\n" if bench else "")
    return f"""# Lumtail

> Lumtail is a command-line tool that follows log files and streams as they grow, reads each
> record in its own format (JSON Lines, syslog, CEF, LEEF, Zeek, Suricata EVE, Kubernetes audit,
> Linux Audit, Fail2ban, Apache and Nginx logs, custom formats) and shows them as one stream
> you can filter. It runs on Linux, macOS, FreeBSD, OpenBSD and NetBSD under the MIT License.

Agents and scripts should use the agent output mode. It writes one compact JSON object per
matching record, with a fixed budget of records, bytes and lines:

{examples}

Each record has the keys timestamp, level, message, file, line and format. Narrow the selection
with --where, --min-level or --filter before raising --limit; read the full record from its file
and line. The schema identifier is urn:lumtail:agent:v1. Use --output json for full fields.

{version}Build from source with CMake 3.24+ and a C++23 compiler:

{build_steps}

## Manual

Markdown renderings of the manual pages installed with Lumtail.

{manuals}

## Agents and scripts

{docs}
{contracts}

## Install

- [Install page]({BASE_URL}download/): binaries for each platform and build steps
- [Releases as JSON]({BASE_URL}download/releases.json): versions, download URLs and SHA-256 digests

## Optional

- [Full documentation]({BASE_URL}llms-full.txt): every manual page and guide above in one file
{performance}- [Security]({BASE_URL}security/): private reporting and published advisories
- [Source code]({GH})

Lumtail and this site are released under the MIT License: {BASE_URL}LICENSE.txt
"""


def llms_full_txt(ctx: dict) -> str:
    parts = [f"{SPDX}\n# Lumtail documentation\n\nAll Lumtail manual pages and agent guides in one file. "
             f"Index: {BASE_URL}llms.txt. License: MIT, see {BASE_URL}LICENSE.txt\n"]
    for m in ctx["manuals"]:
        parts.append(f"Source: {BASE_URL}man/{m['page']}.html\n\n{m['markdown']}")
    for name, _, _, text in ctx["docs"]:
        parts.append(f"Source: {GH}/blob/{ctx['commit']}/docs/{name}\n\n{strip_spdx(text)}")
    return "\n---\n\n".join(parts)


def atom(*, path: str, title: str, link: str, entries: list[dict], updated: str) -> str:
    items = "".join(f"""  <entry>
    <id>{esc(e['id'])}</id>
    <title>{esc(e['title'])}</title>
    <link href="{esc(e['url'])}"/>
    <updated>{esc(e['updated'])}</updated>
    <summary>{esc(e['summary'])}</summary>
  </entry>
""" for e in entries)
    # REUSE-IgnoreStart
    return f"""<?xml version="1.0" encoding="utf-8"?>
<!-- SPDX-FileCopyrightText: 2026 lumtail contributors -->
<!-- SPDX-License-Identifier: MIT -->
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>{BASE_URL}{path}</id>
  <title>{esc(title)}</title>
  <link rel="self" href="{BASE_URL}{path}"/>
  <link href="{link}"/>
  <updated>{updated}</updated>
  <author><name>lumtail contributors</name></author>
{items}</feed>
"""
    # REUSE-IgnoreEnd


# --------------------------------------------------------------------------- main

def build(source: Path, out: Path) -> None:
    if not shutil.which("mandoc"):
        sys.exit("mandoc(1) not found; install it (apt install mandoc, brew install mandoc)")
    commit = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip() or "main"
    ctx = {
        "commit": commit,
        "manuals": [render_manual(source, p) for p in PAGES],
        "releases": read_json("releases.json", []),
        "advisories": read_json("advisories.json", []),
        "license": (source / "LICENSE").read_text(encoding="utf-8"),
        "demos": load_demos(source),
        "bench": load_benchmarks(source),
        "docs":[(name, title, note,
                  absolute_links((source / "docs" / name).read_text(encoding="utf-8"),
                                 f"{GH}/blob/{commit}/docs/"))
                 for name, title, note in AGENT_DOCS if (source / "docs" / name).exists()],
    }
    by_page = {m["page"]: m for m in ctx["manuals"]}
    broken = [p for m in ctx["manuals"] for p in check_manual(m)]
    if broken:
        sys.exit("manual rendering check failed:\n  " + "\n  ".join(broken))
    missing = [f"{m}#{a}" for _, m, a in FORMATS if a not in by_page[m]["ids"]]
    missing += [f"lumtail.1#{a}" for a in ("SECURITY_CONSIDERATIONS", "Workers_and_statistics")
                if a not in by_page["lumtail.1"]["ids"]]
    if missing:
        sys.exit(f"manual anchors missing: {', '.join(missing)}")
    stale = [c for c in AGENT_EXAMPLES if c not in by_page["lumtail-agent.7"]["markdown"]]
    if stale:
        sys.exit(f"agent examples no longer in lumtail-agent(7): {', '.join(stale)}")
    contracts = source / "contracts" / "cli" / "v1"
    absent = [c for c in CONTRACTS if not (contracts / c).exists()]
    if absent:
        sys.exit(f"CLI contract files missing from {contracts}: {', '.join(absent)}")

    files = {
        "index.html": page_index(ctx),
        "man/index.html": page_man_index(ctx),
        "download/index.html": page_download(ctx),
        "security/index.html": page_security(ctx),
        "license/index.html": page_license(ctx),
        "404.html": page_404(ctx),
    }
    for m in ctx["manuals"]:
        files[f"man/{m['page']}.html"] = page_manual(ctx, m)
        files[f"man/{m['page']}.md"] = f"{SPDX}\n{m['markdown']}"
    for name, _, _, text in ctx["docs"]:
        files[f"docs/{name}"] = text
    if ctx["bench"]:
        files["performance/index.html"] = page_performance(ctx)
        files["performance/summary.json"] = json.dumps(bench_summary(ctx["bench"]), indent=2) + "\n"
    files["llms.txt"] = llms_txt(ctx)
    files["llms-full.txt"] = llms_full_txt(ctx)
    files["download/releases.json"] = json.dumps(ctx["releases"], indent=2, ensure_ascii=False) + "\n"

    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rel = [{"id": r["url"], "title": r["name"], "url": r["url"],
            "updated": r["published_at"] or now,
            "summary": f"{len(r['assets'])} files" + (" (pre-release)" if r["prerelease"] else "")}
           for r in ctx["releases"]]
    adv = [{"id": a["url"], "title": f"[{a['severity'].upper()}] {a['summary']}", "url": a["url"],
            "updated": a.get("updated_at") or a.get("published_at") or now,
            "summary": " ".join(filter(None, (a["ghsa"], a.get("cve"))))}
           for a in ctx["advisories"]]
    files["download/releases.xml"] = atom(path="download/releases.xml", title="Lumtail releases",
                                          link=f"{BASE_URL}download/", entries=rel,
                                          updated=max([e["updated"] for e in rel], default=now))
    files["security/advisories.xml"] = atom(path="security/advisories.xml", title="Lumtail security advisories",
                                            link=f"{BASE_URL}security/", entries=adv,
                                            updated=max([e["updated"] for e in adv], default=now))
    pages = [p for p in files if p.endswith(".html") and p != "404.html"]
    files["sitemap.xml"] = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                            + "".join(f"  <url><loc>{BASE_URL}{p.removesuffix('index.html')}</loc></url>\n" for p in sorted(pages))
                            + "</urlset>\n")
    files["robots.txt"] = f"User-agent: *\nAllow: /\nSitemap: {BASE_URL}sitemap.xml\n"

    for rel_path, text in files.items():
        target = out / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    inputs = [source / "man" / p for p in PAGES] + [source / "assets" / a for a in ARTWORK]
    inputs += [source / "assets" / "demo" / f"{stem}.cast" for stem, _ in DEMOS]
    inputs += ctx["bench"]["files"] if ctx["bench"] else []
    inputs += [source / "assets" / "LICENSE", source / "LICENSE"] + sorted(DATA.glob("*.json"))
    inputs += [source / "docs" / name for name, *_ in ctx["docs"]] + [contracts / c for c in CONTRACTS]
    for name in CONTRACTS:
        (out / "cli" / "v1").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(contracts / name, out / "cli" / "v1" / name)
    inputs += [SITE / p for p in (*STATIC, "build.py", "LICENSE")]
    for item in ARTWORK:
        target = out / "assets" / item
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / "assets" / item, target)
    shutil.copyfile(source / "assets" / "LICENSE", out / "assets" / "LICENSE")
    for static in STATIC:
        (out / static).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SITE / static, out / static)
    # The site's own license; .txt keeps it apart from license/ on case-insensitive disks.
    shutil.copyfile(SITE / "LICENSE", out / "LICENSE.txt")

    # Content key: unchanged inputs give the same key, so scheduled runs can skip deploys.
    digest = hashlib.sha256()
    for path in inputs:
        digest.update(path.name.encode() + b"\0" + path.read_bytes())
    write_json(out / "build.json", {"key": digest.hexdigest(), "lumtail": commit})
    print(f"built {len(files)} pages from {source.name} @ {commit[:7]} into {out}")
    print(f"key={digest.hexdigest()}")


def main() -> None:
    global DATA
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=Path, default=SITE.parent / "lumtail",
                        help="lumtail checkout (default: ../lumtail)")
    parser.add_argument("--out", type=Path, default=SITE / "_site", help="output directory (default: _site)")
    parser.add_argument("--data", type=Path, default=DATA, help="release and advisory data (default: data/)")
    parser.add_argument("--sync", action="store_true", help="refresh data/*.json from the GitHub API")
    args = parser.parse_args()
    DATA = args.data.resolve()
    if args.sync:
        sync()
    build(args.source.resolve(), args.out.resolve())


if __name__ == "__main__":
    main()
