# Thin HTTP shim around holehe's CLI, giving `sidecar-holehe` (crates/ozint) a JSON
# endpoint. No official holehe server image exists (megadose/holehe ships a CLI only) — this
# file is that missing sidecar's whole server, verified live 2026-08-25 against a real email
# before being wired into the Rust side.
#
# holehe's CLI has no `--json` flag (checked: `-h` only offers `--csv`), so this shim runs
# `holehe <email> --only-used --no-color -C` in a fresh per-request temp directory, reads the
# CSV it writes, and returns the rows as JSON. `--only-used` still writes a full CSV (every
# site, `exists` true/false) despite its name only filtering the human-readable terminal
# summary — verified by inspecting a real run's output file.
import ast
import csv
import re
import subprocess
import tempfile
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/check")
def check():
    email = request.args.get("email", "")
    if not EMAIL_RE.match(email):
        return jsonify({"error": "missing or malformed `email` query param"}), 400

    with tempfile.TemporaryDirectory() as tmp:
        try:
            subprocess.run(
                ["holehe", email, "--only-used", "--no-color", "-C"],
                cwd=tmp,
                capture_output=True,
                timeout=90,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return jsonify({"error": "holehe timed out after 90s"}), 504

        csv_files = list(Path(tmp).glob("*.csv"))
        if not csv_files:
            # holehe writes no CSV at all if the email fails its own format check before any
            # site is probed — a genuine input-validation failure, not an empty result.
            return jsonify({"error": "holehe produced no output — check email format"}), 422

        rows = []
        with open(csv_files[0], newline="", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                # holehe's own CSV writer (csv.DictWriter) serializes the `others` dict via
                # Python's str() on write, so it round-trips as a Python-literal string like
                # "{'FullName': 'John'}" or "None" — parse it back with ast.literal_eval rather
                # than json, since it's Python repr syntax, not JSON.
                others_raw = row.get("others")
                others = None
                if others_raw and others_raw.strip() and others_raw.strip() != "None":
                    try:
                        others = ast.literal_eval(others_raw)
                    except (ValueError, SyntaxError):
                        others = None

                rows.append(
                    {
                        "name": row.get("name", ""),
                        "domain": row.get("domain", ""),
                        "method": row.get("method", ""),
                        "exists": row.get("exists", "").strip().lower() == "true",
                        "rateLimit": row.get("rateLimit", "").strip().lower() == "true",
                        "frequentRateLimit": row.get("frequent_rate_limit", "").strip().lower() == "true",
                        "emailrecovery": row.get("emailrecovery") or None,
                        "phoneNumber": row.get("phoneNumber") or None,
                        "others": others,
                    }
                )

        return jsonify({"email": email, "results": rows})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5100)
