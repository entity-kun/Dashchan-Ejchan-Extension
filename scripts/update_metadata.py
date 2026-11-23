#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--version", required=True)
parser.add_argument("--apk", required=True)
parser.add_argument("--certificate", required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()

certificate = "".join(ch for ch in args.certificate if ch in "0123456789abcdefABCDEF").upper()
if len(certificate) != 64:
    raise SystemExit("Expected a SHA-256 certificate digest")
fingerprint = ":".join(certificate[i:i + 2] for i in range(0, 64, 2))
apk = Path(args.apk)

payload = {
    "meta": {"repository": "Dashchan Ejchan Extension"},
    "ejchan": [{
        "title": "Release",
        "name": args.version,
        "code": 1,
        "minVersion": 1,
        "maxVersion": 1,
        "minSdk": 16,
        "length": apk.stat().st_size,
        "source": f"//github.com/entity-kun/Dashchan-Ejchan-Extension/releases/download/v{args.version}/DashchanEjchan-{args.version}.apk",
        "fingerprint": fingerprint,
    }],
}
Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
