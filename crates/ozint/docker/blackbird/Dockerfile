# `sidecar-blackbird-*` — no official server image exists for Blackbird (p1ngul1n0/blackbird
# ships a CLI only), so this builds one: Blackbird + a thin Flask JSON shim (app.py) around its
# `--json` export. See `crates/ozint/src/sources/sidecar/blackbird.rs` for the Rust-side
# caller and `app.py` for why the shim serialises requests (Blackbird's own JSON export path is
# fixed relative to its install directory, not request-isolated like holehe's).
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Pinned to an exact commit so the image is reproducible and so an upstream change has to be
# adopted deliberately rather than arriving with the next rebuild. Blackbird is **GPLv3**
# (`docs/LICENSE` in its own tree); it is fetched at build time and never redistributed by this
# repository, which is MIT. Its shape as of this commit: 700+ WhatsMyName sites for username
# mode, a 16-site curated list with declarative per-site metadata extraction for email mode.
ARG BLACKBIRD_REF=b45505080ef51bb3ef52dc29879ee6bef31e5b94
RUN git clone https://github.com/p1ngul1n0/blackbird.git /app/blackbird \
    && git -C /app/blackbird checkout --quiet "$BLACKBIRD_REF" \
    && pip install --no-cache-dir -r /app/blackbird/requirements.txt \
    && pip install --no-cache-dir flask==3.* gunicorn==23.*

# Local overlay, applied to the clone rather than shipped as a modified copy: a patched
# `email-data.json` would be a GPL-derived file living in an MIT repository. `patch-email-data.py`
# is ours, it adds a metadata-extraction spec to two of Blackbird's sixteen email-mode sites
# (Duolingo and Spotify, whose endpoints already return more than Blackbird reads), and it fails
# the build rather than degrading if either site has moved. Its docstring carries the detail.
COPY patch-email-data.py .
RUN python3 patch-email-data.py /app/blackbird/data/email-data.json

# Blackbird's own repo does not ship `data/wmn-data.json` (username mode's WhatsMyName site
# list, ~700 sites) — it downloads it on first run via `checkUpdates()`, keyed on
# `USERNAME_LIST_PATH` being relative to `os.getcwd()`, not the package directory (verified by
# reading `src/config.py` after a live run crashed with `FileNotFoundError` under `--no-update`
# on an image that never triggered that first download). Fetched directly here (the same URL
# `checkUpdates()`/`downloadList()` would hit) rather than by running the CLI once, which would
# also fire a real, wasted 700-site sweep against a throwaway username. `email-data.json` needs
# no such step — it already ships in the repo.
RUN curl -fsSL https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json \
    -o /app/blackbird/data/wmn-data.json

WORKDIR /app
COPY app.py .

EXPOSE 5200
CMD ["gunicorn", "--bind", "0.0.0.0:5200", "--workers", "1", "--timeout", "180", "app:app"]
