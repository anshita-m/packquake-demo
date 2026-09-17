"""Generate synthetic-but-realistic CycloneDX SBOMs for the 4 target apps.

PLACEHOLDER DATA. Each app in `data/sbom/` should eventually be regenerated
from the real repo with:

    syft dir:./appN -o cyclonedx-json > data/sbom/<app_id>.json

This script exists only so Phase 2 (parsing/graph-building) can be built and
tested before those real scans are run. It writes the exact same filenames
Syft output would use, so swapping in real scans requires no code changes.

Deliberately includes the two "planted" shared packages so the graph has
something to demo:
  - lodash@4.17.21   (npm)  -> hackathon-starter, node-realworld
  - requests@2.31.0  (pypi) -> microblog, flack

(django-realworld was a 5th app originally included for the same purpose,
plus real old/vulnerable pins for Phase 3 demo purposes -- dropped from the
project, no longer generated here.)
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SBOM_DIR = REPO_ROOT / "data" / "sbom"

# Per-app spec: ecosystem, root app version, direct dependency names, and a
# full package table of {name: (version, [transitive dep names])} covering
# every direct dep plus a couple of levels of transitive deps.
APPS: dict[str, dict] = {
    "hackathon-starter": {
        "ecosystem": "npm",
        "root_version": "1.0.0",
        "direct": [
            "express", "mongoose", "passport", "passport-local", "lodash",
            "body-parser", "ejs", "async", "dotenv", "chalk", "nodemailer", "multer",
        ],
        "packages": {
            "express": ("4.18.2", ["accepts", "finalhandler"]),
            "accepts": ("1.3.8", ["mime-types"]),
            "mime-types": ("2.1.35", []),
            "finalhandler": ("1.2.0", []),
            "mongoose": ("7.6.3", ["mquery", "kareem"]),
            "mquery": ("5.0.0", []),
            "kareem": ("2.5.1", []),
            "passport": ("0.6.0", []),
            "passport-local": ("1.0.0", ["passport-strategy"]),
            "passport-strategy": ("1.0.0", []),
            "lodash": ("4.17.21", []),
            "body-parser": ("1.20.2", ["bytes", "content-type"]),
            "bytes": ("3.1.2", []),
            "content-type": ("1.0.5", []),
            "ejs": ("3.1.9", []),
            "async": ("3.2.4", []),
            "dotenv": ("16.3.1", []),
            "chalk": ("4.1.2", ["ansi-styles"]),
            "ansi-styles": ("4.3.0", []),
            "nodemailer": ("6.9.5", []),
            "multer": ("1.4.5-lts.1", ["busboy"]),
            "busboy": ("1.6.0", []),
        },
    },
    "node-realworld": {
        "ecosystem": "npm",
        "root_version": "1.0.0",
        "direct": [
            "express", "jsonwebtoken", "bcryptjs", "body-parser", "mongoose",
            "lodash", "morgan", "cors", "dotenv", "typescript", "ts-node", "method-override",
        ],
        "packages": {
            "express": ("4.18.2", ["accepts", "finalhandler"]),
            "accepts": ("1.3.8", ["mime-types"]),
            "mime-types": ("2.1.35", []),
            "finalhandler": ("1.2.0", []),
            "jsonwebtoken": ("9.0.2", ["jws"]),
            "jws": ("4.0.0", []),
            "bcryptjs": ("2.4.3", []),
            "body-parser": ("1.20.2", ["bytes", "content-type"]),
            "bytes": ("3.1.2", []),
            "content-type": ("1.0.5", []),
            "mongoose": ("7.6.3", ["mquery", "kareem"]),
            "mquery": ("5.0.0", []),
            "kareem": ("2.5.1", []),
            "lodash": ("4.17.21", []),
            "morgan": ("1.10.0", ["basic-auth"]),
            "basic-auth": ("2.0.1", []),
            "cors": ("2.8.5", []),
            "dotenv": ("16.3.1", []),
            "typescript": ("5.2.2", []),
            "ts-node": ("10.9.1", ["typescript"]),
            "method-override": ("3.0.0", []),
        },
    },
    "microblog": {
        "ecosystem": "pypi",
        "root_version": "1.0.0",
        "direct": [
            "flask", "flask-login", "flask-sqlalchemy", "flask-wtf", "flask-mail",
            "flask-migrate", "requests", "requests-toolbelt", "python-dotenv",
            "email-validator", "pyjwt", "redis",
        ],
        "packages": {
            "flask": ("3.0.0", ["werkzeug", "jinja2", "click", "itsdangerous", "blinker"]),
            "werkzeug": ("3.0.1", []),
            "jinja2": ("3.1.2", ["markupsafe"]),
            "markupsafe": ("2.1.3", []),
            "click": ("8.1.7", []),
            "itsdangerous": ("2.1.2", []),
            "blinker": ("1.6.3", []),
            "flask-login": ("0.6.3", []),
            "flask-sqlalchemy": ("3.1.1", ["sqlalchemy"]),
            "sqlalchemy": ("2.0.23", []),
            "flask-wtf": ("1.2.1", ["wtforms"]),
            "wtforms": ("3.1.1", []),
            "flask-mail": ("0.9.1", []),
            "flask-migrate": ("4.0.5", []),
            "requests": ("2.31.0", ["urllib3", "certifi", "charset-normalizer", "idna"]),
            "requests-toolbelt": ("1.0.0", ["requests"]),
            "urllib3": ("2.0.7", []),
            "certifi": ("2023.7.22", []),
            "charset-normalizer": ("3.3.1", []),
            "idna": ("3.4", []),
            "python-dotenv": ("1.0.0", []),
            "email-validator": ("2.1.0", []),
            "pyjwt": ("2.8.0", []),
            "redis": ("5.0.1", []),
        },
    },
    "flack": {
        "ecosystem": "pypi",
        "root_version": "1.0.0",
        "direct": [
            "flask", "flask-socketio", "celery", "redis", "requests",
            "python-socketio", "python-engineio", "gunicorn", "eventlet",
        ],
        "packages": {
            "flask": ("3.0.0", ["werkzeug", "jinja2", "click", "itsdangerous", "blinker"]),
            "werkzeug": ("3.0.1", []),
            "jinja2": ("3.1.2", ["markupsafe"]),
            "markupsafe": ("2.1.3", []),
            "click": ("8.1.7", []),
            "itsdangerous": ("2.1.2", []),
            "blinker": ("1.6.3", []),
            "flask-socketio": ("5.3.6", ["python-socketio"]),
            "celery": ("5.3.4", ["kombu", "billiard", "vine"]),
            "kombu": ("5.3.3", []),
            "billiard": ("4.2.0", []),
            "vine": ("5.1.0", []),
            "redis": ("5.0.1", []),
            "requests": ("2.31.0", ["urllib3", "certifi", "charset-normalizer", "idna"]),
            "urllib3": ("2.0.7", []),
            "certifi": ("2023.7.22", []),
            "charset-normalizer": ("3.3.1", []),
            "idna": ("3.4", []),
            "python-socketio": ("5.10.0", []),
            "python-engineio": ("4.8.0", []),
            "gunicorn": ("21.2.0", []),
            "eventlet": ("0.33.3", []),
        },
    },
}


def purl_for(ecosystem: str, name: str, version: str) -> str:
    return f"pkg:{ecosystem}/{name}@{version}"


def build_document(app_id: str, spec: dict) -> dict:
    ecosystem = spec["ecosystem"]
    root_ref = f"urn:app:{app_id}"

    components = []
    for name, (version, _deps) in spec["packages"].items():
        purl = purl_for(ecosystem, name, version)
        components.append({
            "bom-ref": purl,
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
        })

    dependencies = [{
        "ref": root_ref,
        "dependsOn": [purl_for(ecosystem, name, spec["packages"][name][0]) for name in spec["direct"]],
    }]
    for name, (version, deps) in spec["packages"].items():
        if not deps:
            continue
        dependencies.append({
            "ref": purl_for(ecosystem, name, version),
            "dependsOn": [purl_for(ecosystem, dep, spec["packages"][dep][0]) for dep in deps],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:00000000-0000-0000-0000-{abs(hash(app_id)) % 10**12:012d}",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": root_ref,
                "type": "application",
                "name": app_id,
                "version": spec["root_version"],
            },
        },
        "components": components,
        "dependencies": dependencies,
    }


def main() -> None:
    SBOM_DIR.mkdir(parents=True, exist_ok=True)
    for app_id, spec in APPS.items():
        doc = build_document(app_id, spec)
        out_path = SBOM_DIR / f"{app_id}.json"
        out_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {out_path} ({len(doc['components'])} components)")


if __name__ == "__main__":
    main()
