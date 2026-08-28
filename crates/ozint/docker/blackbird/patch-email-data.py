#!/usr/bin/env python3
"""Add metadata-extraction specs to two of Blackbird's email-mode sites, in place.

Why this exists as a patch script rather than as a copy of the file it patches: Blackbird is
GPLv3 and this project is MIT. Shipping a modified copy of `email-data.json` would distribute a
GPL-derived work from an MIT repository. Patching the file inside the image, after the clone,
keeps the derived artefact where it belongs — in a build directory, under Blackbird's own
licence — and leaves this repository holding only its own thirty lines.

What it patches: two of Blackbird's own sixteen email-mode sites carry no metadata spec even
though their existence-check endpoint already returns richer JSON. Verified live 2026-08-26 by
calling both directly. Duolingo's `.../users?email=` answers
`{"users":[{"hasGoogleId":…,"hasFacebookId":…,"hasPlus":…,"streak":…,"username":…,"picture":…}]}`;
Spotify's `.../signup/public/v1/account?validate=1` answers with `country`/`minimum_age`
alongside the taken/available boolean.

One limitation carried over from Blackbird's own `extractMetadata`, and not ours to fix without
forking it: a falsy extracted value (`hasGoogleId: false`, `streak: 0`) is treated as "nothing
found" and silently omitted, so only truthy hits surface.

This fails loudly rather than degrading. A site that has gone missing, or that upstream has since
given its own metadata spec, stops the build — the alternative is an image that silently returns
less than the caller expects, discovered much later and nowhere near the cause.
"""

import json
import sys

PATCHES = {
    "Duolingo": [
        {"schema": "JSON", "type": "String", "name": "Has Google ID", "path": ["users", 0, "hasGoogleId"]},
        {"schema": "JSON", "type": "String", "name": "Has Facebook ID", "path": ["users", 0, "hasFacebookId"]},
        {"schema": "JSON", "type": "String", "name": "Has Plus (subscriber)", "path": ["users", 0, "hasPlus"]},
        {"schema": "JSON", "type": "String", "name": "Streak", "path": ["users", 0, "streak"]},
        {"schema": "JSON", "type": "String", "name": "Username", "path": ["users", 0, "username"]},
        {"schema": "JSON", "type": "Image", "name": "Picture", "path": ["users", 0, "picture"]},
    ],
    "Spotify": [
        {"schema": "JSON", "type": "String", "name": "Country", "path": ["country"]},
        {"schema": "JSON", "type": "String", "name": "Minimum Age", "path": ["minimum_age"]},
    ],
}


def main(path: str) -> int:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)

    by_name = {site.get("name"): site for site in data.get("sites", [])}

    for name, metadata in PATCHES.items():
        site = by_name.get(name)
        if site is None:
            print(f"patch-email-data: '{name}' is no longer in Blackbird's email site list", file=sys.stderr)
            return 1
        if site.get("metadata"):
            print(
                f"patch-email-data: '{name}' now carries its own metadata spec upstream — "
                "review it and drop this patch entry rather than overwriting it",
                file=sys.stderr,
            )
            return 1
        site["metadata"] = metadata

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=4)

    print(f"patch-email-data: patched {', '.join(PATCHES)} in {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "/app/blackbird/data/email-data.json"))
