# Security policy

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private vulnerability reporting on this
repository — the *Report a vulnerability* button under the **Security** tab. If that is not
available to you, open a normal issue saying only that you have a security report and asking for
a contact address, with no detail in it.

This is a one-person project maintained in evenings. Expect an acknowledgement within a week or
so, not within hours. There is no bounty.

## What is in scope

This tool runs on the reporter's own machine and binds loopback, so the interesting cases are
mostly about it being made to act against its operator rather than about a remote attacker:

- **SSRF.** `ozint-core`'s `net` guard screens outbound URLs, and `http.rs` re-runs that screen on
  every redirect hop. A way past either — or a tool that reaches the network without going
  through the shared client — is in scope.
- **Leaking the analyst's seed.** The seed is often the most identifying thing anyone types into
  this cockpit. Any path that sends it somewhere the analyst did not choose — including through
  the optional LLM tier, which is meant to be gated by `ozint::egress` — is in scope.
- **Defeating the kill switch.** A frozen instance must make no outbound call. A gated route that
  reaches the network anyway, or a way to make the freeze record read as unfrozen when it is not,
  is in scope.
- **Path traversal or arbitrary read/write** through the media store, the dossier export, or any
  path derived from user input.
- **Command injection** into the binaries this shells out to (`ffmpeg`, `ffprobe`, `yt-dlp`) or
  into a sidecar request.

## What is not in scope

- **The absence of authentication.** There is none, deliberately, which is why the server binds
  `127.0.0.1` and not `0.0.0.0`. Exposing it on a network without a reverse proxy in front is a
  deployment choice, and its consequences are not a vulnerability in this project.
- **Rate-limit evasion against upstreams**, or anything whose impact is on a third-party API
  rather than on the operator.
- **Vulnerabilities in the sidecars themselves** (Blackbird, holehe, Maigret, SpiderFoot) — report
  those to their own projects. How OZINT *talks* to them is in scope.
- **The tool doing what it is for.** OZINT queries public data about a subject; that is its
  purpose, and misuse of it is addressed in the README's responsible-use section rather than here.

## A note on the known blind spot

[STATUS.md](STATUS.md) records that most source tests exercise the parser rather than the request.
That is a correctness gap rather than a security one, but it is worth knowing before you conclude
from a green suite that a network path behaves as documented.
