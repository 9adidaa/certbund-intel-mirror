#!/usr/bin/env python3

import json
import re
from pathlib import Path


ROOT = Path("database/raw/certbund")
OUTPUT = Path("database/intel/certbund_cve_first_seen.json")

CVE_REGEX = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")


def extract_date(obj):
    # CSAF usually has:
    # document -> tracking -> initial_release_date
    try:
        return obj["document"]["tracking"]["initial_release_date"]
    except Exception:
        return None


def main():
    first_seen = {}

    for file in sorted(ROOT.rglob("*.json")):
        advisory_id = file.stem

        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except Exception:
            continue

        blob = json.dumps(data, ensure_ascii=False)
        cves = {c.upper() for c in CVE_REGEX.findall(blob)}

        date = extract_date(data)

        for cve in cves:
            if cve not in first_seen:
                first_seen[cve] = {
                    "first_seen_in": advisory_id,
                    "first_seen_date": date,
                }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(first_seen, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("CVE tracked:", len(first_seen))


if __name__ == "__main__":
    main()
