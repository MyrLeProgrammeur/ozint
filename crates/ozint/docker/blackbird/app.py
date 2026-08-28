# Thin HTTP shim around Blackbird's CLI, giving `sidecar-blackbird-username`/
# `sidecar-blackbird-email` (crates/ozint) a JSON endpoint. No official Blackbird server
# image exists (p1ngul1n0/blackbird ships a CLI only) — this file is that missing sidecar's
# whole server, mirroring `docker/holehe/app.py`'s shape.
#
# Unlike holehe, Blackbird's own `--json` export does not write to a per-request temp
# directory: `generateName()`/`createSaveDirectory()` resolve `results/<identifier>_<date>_
# blackbird/` relative to Blackbird's *install* directory (`os.path.dirname(__file__)` inside
# its own package), the same path regardless of this shim's CWD. Two requests in flight would
# race on that path, so this shim serialises every run behind a lock and wipes the results
# directory clean after each read — Blackbird itself also skips writing a JSON file at all when
# zero accounts were found (`saveToJson` is only called `if config.json and
# config.usernameFoundAccounts`), which this shim treats as a genuine empty result, not a
# failure.
import glob
import json
import re
import shutil
import subprocess
import threading

from flask import Flask, jsonify, request

app = Flask(__name__)

BLACKBIRD_DIR = "/app/blackbird"
RESULTS_GLOB = f"{BLACKBIRD_DIR}/results/**/*.json"
RUN_LOCK = threading.Lock()

# Loose on purpose: Blackbird accepts free-form email/username strings itself and does its own
# validation; this shim only guards against control characters/whitespace reaching a subprocess
# argv, not against a value that later turns out not to look like an email.
VALUE_RE = re.compile(r"^\S+$")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


def _clear_results():
    shutil.rmtree(f"{BLACKBIRD_DIR}/results", ignore_errors=True)


@app.get("/check")
def check():
    mode = request.args.get("mode", "")
    value = request.args.get("value", "")
    if mode not in ("username", "email"):
        return jsonify({"error": "`mode` must be `username` or `email`"}), 400
    if not VALUE_RE.match(value):
        return jsonify({"error": "missing or malformed `value` query param"}), 400

    flag = "--username" if mode == "username" else "--email"

    with RUN_LOCK:
        _clear_results()
        try:
            subprocess.run(
                ["python3", "blackbird.py", flag, value, "--json", "--no-update"],
                cwd=BLACKBIRD_DIR,
                capture_output=True,
                timeout=150,
                check=False,
            )
        except subprocess.TimeoutExpired:
            _clear_results()
            return jsonify({"error": "blackbird timed out after 150s"}), 504

        json_files = glob.glob(RESULTS_GLOB, recursive=True)
        if not json_files:
            # No file at all is Blackbird's own convention for "zero accounts found" — a
            # genuine empty result, not a probe failure.
            return jsonify({mode: value, "results": []})

        with open(json_files[0], encoding="utf-8", errors="replace") as f:
            results = json.load(f)
        _clear_results()

        return jsonify({mode: value, "results": results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5200)
