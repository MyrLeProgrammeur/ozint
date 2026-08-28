# `sidecar-holehe` — no official server image exists for holehe (megadose/holehe ships a CLI
# only), so this builds one: holehe + a thin Flask JSON shim (app.py) around its `-C`/CSV
# output. See `crates/ozint/src/sources/sidecar/holehe.rs` for the Rust-side caller and
# `app.py` for why CSV rather than a `--json` flag (holehe has none).
FROM python:3.12-slim

RUN pip install --no-cache-dir holehe==1.61 flask==3.* gunicorn==23.*

WORKDIR /app
COPY app.py .

EXPOSE 5100
CMD ["gunicorn", "--bind", "0.0.0.0:5100", "--workers", "2", "--timeout", "120", "app:app"]
