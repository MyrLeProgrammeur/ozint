# Credits and attribution

OZINT queries other people's data. Several of those sources require attribution as a condition
of their licence — not as a courtesy — and this file is where that obligation is met.

**It is enforced, not maintained by hand.** Each tool in
[`crates/ozint/src/registry.rs`](crates/ozint/src/registry.rs) declares an `attribution` string
when its source requires one, and a test (`registry::tests::every_declared_attribution_is_credited`)
fails the build if any of those strings is missing from this file. Adding a source with an
attribution requirement and forgetting to credit it is therefore a red suite, not a silent
licence breach — which is how this gap went unnoticed for as long as it did.

If you are adding a source: put the attribution in its `ToolDef`, then add the line here.

---

## Data sources

| Source | Attribution |
|---|---|
| **WhatsMyName** (`wmn-probe`, and `sidecar-blackbird-username`, which uses the same site list) | Site list © WhatsMyName contributors (WebBreacher), **CC BY-SA 4.0** — https://github.com/WebBreacher/WhatsMyName |
| **FIRST.org EPSS** (`cve-epss`) | EPSS scores © FIRST.org — https://www.first.org/epss/ |
| **MaxMind GeoLite2** (`ip-maxmind`) | This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com |
| **OpenStreetMap** (`geo-nominatim`, `geo-overpass`) | © OpenStreetMap contributors |
| **IPinfo** (`ip-ipinfo`) | IP geolocation by IPinfo |
| **Shodan InternetDB** (`ip-internetdb`) | Exposure data from Shodan InternetDB |
| **PeeringDB** (`ip-peeringdb`) | Network data from PeeringDB |
| **AbuseIPDB** (`ip-abuseipdb`) | Abuse reports from AbuseIPDB |
| **GreyNoise** (`ip-greynoise`) | Noise classification from GreyNoise |
| **Censys** (`ip-censys`) | Host data from Censys |
| **Netlas** (`ip-netlas`) | Host data from Netlas |
| **SauceNAO** (`img-saucenao`) | Reverse-image matches from SauceNAO |

Sources not listed here impose no attribution requirement that this project could find in their
terms. That is a statement about what was checked, not a guarantee — if you know otherwise for
one of them, that is a genuinely useful issue to open.

## Bundled third-party tools

Four optional sidecars are built as Docker images. Their code is fetched at build time and
**none of it is redistributed by this repository**; each remains under its own licence.

| Tool | Licence | Source |
|---|---|---|
| **Blackbird** | GPLv3 | https://github.com/p1ngul1n0/blackbird |
| **holehe** | GPLv3 | https://github.com/megadose/holehe |
| **Maigret** | MIT | https://github.com/soxoj/maigret |
| **SpiderFoot** | MIT | https://github.com/smicallef/spiderfoot |

`crates/ozint/docker/blackbird/patch-email-data.py` adds a metadata-extraction spec to two
entries of Blackbird's own `email-data.json`. It is applied to the clone inside the image
precisely so that no GPL-derived file is ever committed to this MIT repository.

Two further binaries are shelled out to when present, and are not bundled:
**ffmpeg/ffprobe** (LGPL/GPL depending on build) and **yt-dlp** (Unlicense).

## The project itself

OZINT is MIT licensed — see [LICENSE](LICENSE). Its Rust and JavaScript dependencies are
declared in `Cargo.toml` and `web/package.json`; run `cargo tree` or `npm ls` for the full
resolved set.
