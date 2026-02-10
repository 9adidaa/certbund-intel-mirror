import json
import re
from pathlib import Path


# =============================
# CONFIG
# =============================

ROOT = Path("bsi_csaf_dump")
OUTPUT_FILE = Path("certbund_unique_cves.json")

CVE_REGEX = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")


# =============================
# MAIN
# =============================

def main():
    files = list(ROOT.rglob("*.json"))
    total_files = len(files)

    all_cves = set()
    error_files = 0

    for idx, file in enumerate(files, start=1):
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[!] error reading {file}: {e}")
            error_files += 1
            continue

        blob = json.dumps(data, ensure_ascii=False)
        found = {c.upper() for c in CVE_REGEX.findall(blob)}
        all_cves.update(found)

        # 📊 progress
        percent = (idx / total_files) * 100
        print(
            f"[{idx}/{total_files}] {percent:6.2f}% "
            f"| unique CVEs so far: {len(all_cves)}",
            end="\r"
        )

    print()  # newline after progress

    sorted_cves = sorted(all_cves)

    OUTPUT_FILE.write_text(
        json.dumps(sorted_cves, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("\n========== DONE ==========")
    print("files scanned :", total_files)
    print("errors        :", error_files)
    print("unique CVEs   :", len(sorted_cves))
    print("output file   :", OUTPUT_FILE.resolve())


if __name__ == "__main__":
    main()
