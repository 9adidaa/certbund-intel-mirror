import subprocess
import sys

STEPS = [
    ("Mirror CERT-Bund", "python database/scripts/mirror.py"),
    ("Build CVE list", "python database/scripts/build_cve_index.py"),
    ("Build first-seen intel", "python database/scripts/build_first_seen.py"),
]


def run():
    for name, cmd in STEPS:
        print(f"\n===== {name} =====")
        r = subprocess.run(cmd, shell=True)
        if r.returncode != 0:
            return r.returncode
    return 0

if __name__ == "__main__":
    sys.exit(run())
