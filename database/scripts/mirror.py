import json
import hashlib
import time
import requests
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List

# ------------------------------
# CONFIG
# ------------------------------

TIMEOUT = 30
SLEEP_ON_ERROR = 1.0  # seconds
RETRIES = 3

HEADERS = {
    "User-Agent": "BSI-CERTBund-Mirror/2.0 (+mokda project)",
    "Accept": "application/json, */*",
}

FEEDS = {
    # General BSI advisories (biggest coverage)
    "bsi": "https://wid.cert-bund.de/.well-known/csaf/white/bsi-white.json",

    # WID portal advisories (Kurzinformationen)
    "bsi-wid": "https://wid.cert-bund.de/.well-known/csaf/white/bsi-wid-white.json",

    # Coordinated vulnerability disclosure
    "bsi-cvd": "https://wid.cert-bund.de/.well-known/csaf/white/bsi-cvd-white.json",
}

OUT_DIR = Path("database/raw/certbund")


# ------------------------------
# HELPERS
# ------------------------------

def stable_hash(obj: Dict[str, Any]) -> str:
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def json_should_update(path: Path, new_obj: Dict[str, Any]) -> bool:
    """Compare stable hash of JSON documents."""
    if not path.exists():
        return True
    try:
        old_obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return True
    return stable_hash(old_obj) != stable_hash(new_obj)


def save_json(path: Path, obj: Dict[str, Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def extract_year_from_url(url: str) -> str:
    # Example:
    # /.../csaf/white/2026/wid-sec-w-2026-0231.json
    parts = urlparse(url).path.strip("/").split("/")
    for p in parts:
        if p.isdigit() and len(p) == 4:
            return p
    # fallback: use current year
    return str(datetime.utcnow().year)


def request_with_retries(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs
) -> requests.Response:
    last_exc = None
    for attempt in range(1, RETRIES + 1):
        try:
            r = session.request(method, url, timeout=TIMEOUT, headers=HEADERS, **kwargs)
            return r
        except Exception as e:
            last_exc = e
            if attempt < RETRIES:
                time.sleep(0.5 * attempt)
    raise RuntimeError(f"Failed request after {RETRIES} retries: {url}\n{last_exc}")


def fetch_json(session: requests.Session, url: str) -> Tuple[Optional[Dict[str, Any]], Any]:
    """Fetch JSON safely. Returns (json_obj, status)."""
    r = request_with_retries(session, "GET", url)
    if r.status_code != 200:
        return None, r.status_code

    ctype = (r.headers.get("Content-Type") or "").lower()
    if "application/json" not in ctype and "json" not in ctype:
        # some servers send application/octet-stream for json
        try:
            return r.json(), 200
        except Exception:
            return None, "not_json"

    try:
        return r.json(), 200
    except Exception:
        return None, "json_decode_error"


def download_binary(session: requests.Session, url: str, out_path: Path) -> Any:
    """Download .asc / .sha512 etc."""
    r = request_with_retries(session, "GET", url)
    if r.status_code != 200:
        return r.status_code
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(r.content)
    return 200


def normalize_id(entry: Dict[str, Any], advisory_url: str) -> str:
    # prefer entry id, otherwise file name without extension
    adv_id = entry.get("id")
    if adv_id:
        return adv_id
    return Path(urlparse(advisory_url).path).name.replace(".json", "")


# ------------------------------
# CORE
# ------------------------------

def parse_feed_entries(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries = feed.get("feed", {}).get("entry", [])
    if not isinstance(entries, list):
        return []
    return entries


def mirror_feed(feed_name: str, feed_url: str, base_dir: Path, session: requests.Session):
    print(f"\n===== FEED: {feed_name} =====")
    print(f"URL: {feed_url}")

    feed_obj, status = fetch_json(session, feed_url)
    if status != 200 or not feed_obj:
        print(f"[!] Cannot download feed {feed_name}: {status}")
        return

    # Save feed index itself
    feed_index_path = base_dir / "_feeds" / f"{feed_name}.json"
    if json_should_update(feed_index_path, feed_obj):
        save_json(feed_index_path, feed_obj)

    entries = parse_feed_entries(feed_obj)
    print(f"Entries in feed: {len(entries)}")

    downloaded = updated = skipped = errors = sigs = hashes = 0

    for idx, entry in enumerate(entries, 1):
        advisory_url = entry.get("content", {}).get("src")
        if not advisory_url:
            continue

        year = extract_year_from_url(advisory_url)
        adv_id = normalize_id(entry, advisory_url)

        out_file = base_dir / year / feed_name / f"{adv_id}.json"

        obj, st = fetch_json(session, advisory_url)
        if st != 200 or not obj:
            errors += 1
            print(f"[!] {idx}/{len(entries)} {adv_id}: error {st}")
            time.sleep(SLEEP_ON_ERROR)
            continue

        if json_should_update(out_file, obj):
            if out_file.exists():
                updated += 1
                print(f"[U] {year}/{feed_name}/{adv_id}")
            else:
                downloaded += 1
                print(f"[+] {year}/{feed_name}/{adv_id}")
            save_json(out_file, obj)
        else:
            skipped += 1

        # download signature + hash if present
        links = entry.get("link", [])
        if isinstance(links, list):
            for l in links:
                href = l.get("href")
                rel = l.get("rel")
                if not href or rel not in ("signature", "hash"):
                    continue

                if rel == "signature":
                    sig_path = out_file.with_suffix(out_file.suffix + ".asc")
                    code = download_binary(session, href, sig_path)
                    if code == 200:
                        sigs += 1
                elif rel == "hash":
                    hash_path = out_file.with_suffix(out_file.suffix + ".sha512")
                    code = download_binary(session, href, hash_path)
                    if code == 200:
                        hashes += 1

    print(
        f"Done feed={feed_name}: "
        f"new={downloaded}, updated={updated}, skipped={skipped}, "
        f"errors={errors}, sigs={sigs}, hashes={hashes}"
    )


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with requests.Session() as session:
        for feed_name, feed_url in FEEDS.items():
            mirror_feed(feed_name, feed_url, OUT_DIR, session)


if __name__ == "__main__":
    main()
