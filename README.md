<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# lumtail.github.io

Source for <https://lumtail.github.io>: the Lumtail home page, manual pages,
downloads and security advisories.

## Build

Needs Python 3.10+ and [mandoc](https://mandoc.bsd.lv/), with
[lumtail](https://github.com/lumtail/lumtail) checked out next to this repository.

```sh
python3 build.py                        # writes _site/ from ../lumtail and data/*.json
python3 build.py --sync                 # refresh releases and advisories from GitHub first
python3 -m http.server -d _site 8000    # preview at http://127.0.0.1:8000
python3 -m unittest discover -s tests   # build script tests
```

`build.py` renders `man/*.[157]` with `mandoc -Thtml` into the site layout,
copies the artwork from `lumtail/assets` and writes the pages, Atom feeds,
sitemap and `build.json`.

For agents it also writes `llms.txt`, `llms-full.txt` (the manual and
`docs/agents.md`, `docs/cli-api.md` in one file; both guides are also served
under `docs/`), a Markdown copy of each manual
page (`mandoc -Tmarkdown`), `download/releases.json` and the CLI API 1 schemas
from `contracts/cli/v1/` under `cli/v1/`.

`performance/` shows the newest run in `benchmarks/results/<revision>/` that has
`public-logs.json`, `stress-1m.json` and `suite.json`, states whether the code
changed after that revision, and repeats the figures in `performance/summary.json`. Markup from mandoc 1.14.6 (Debian, Ubuntu) and newer
releases is normalized to one form. The build stops if a page loses its sections
or a linked anchor disappears.

Generated files are not committed; the workflow builds and deploys them.

## Updates

The [Pages workflow](.github/workflows/pages.yml) deploys on:

| Trigger | When |
| --- | --- |
| `lumtail-updated` dispatch | Sent by [`site.yml`](https://github.com/lumtail/lumtail/blob/main/.github/workflows/site.yml) in lumtail/lumtail when it publishes a release or pushes to `main` touching `man/`, `assets/img/`, `assets/demo/`, `assets/LICENSE`, `LICENSE`, `README.md`, `docs/agents.md`, `docs/cli-api.md` or `contracts/cli/v1/` |
| Schedule, every 6 hours | Deploys only when the content key differs from the live `build.json` (covers advisories and missed dispatches) |
| Push here, manual run | Always |

## Data

| File | Source |
| --- | --- |
| `data/releases.json` | GitHub Releases without drafts; asset SHA-256 from the release digest |
| `data/advisories.json` | Published GitHub Security Advisories of lumtail/lumtail |

When there is no release, the site offers building from source; when there is
no advisory, Security leaves the main menu and its feed is not advertised.
Readers' browsers make no requests to GitHub.

## License

Code, text and artwork are MIT, `Copyright (c) 2026 lumtail contributors`.
The build copies lumtail's `assets/img` and `assets/demo` files unchanged,
with their `.license` companions and `assets/LICENSE`.
Manual page HTML is rendered from MIT-licensed mdoc sources. mandoc is a build
tool only; none of its code or stylesheet is in the output. Type uses installed
system fonts; no font files are distributed.
