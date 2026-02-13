#!/usr/bin/env python3

import json
import hashlib
import time
import requests
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List


# ==========================================================
# CONFIG
# ==========================================================

TIMEOUT = 30
RETRIES = 3
SLEEP_ON_ERROR = 1.0

HEADERS = {
    "User-Agent": "CERTBund-Mirror/5.0 (+mokda project)",
    "Accept": "application/json, */*",
}

FEEDS = {
    "bsi": "https://wid.cert-bund.de/.well-known/csaf/white/bsi-white.json",
    "bsi-wid": "https://wid.cert-bund.de/.well-known/csaf/white/bsi-wid-white.json",
    "bsi-cvd": "https://wid.cert-bund.de/.well-known/csaf/white/bsi-cvd-white.json",
}

OUT_DIR = Path("database/raw/certbund")


# ==========================================================
# HASH / IO
# ==========================================================

def stable_hash(obj: Dict[str, Any]) -> str:
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def json_should_update(path: Path, new_obj: Dict[str, Any]) -> bool:
    if not path.exists():
        return True
    try:
        old = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return True
    return stable_hash(old) != stable_hash(new_obj)


def save_json(path: Path, obj: Dict[str, Any]):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def read_text_safe(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8").strip()
    except Exception:
        return None


def write_text_safe(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ==========================================================
# NETWORK
# ==========================================================

def request_with_retries(session: requests.Session, url: str) -> requests.Response:
    last_exc = None
    for i in range(RETRIES):
        try:
            return session.get(url, headers=HEADERS, timeout=TIMEOUT)
        except Exception as e:
            last_exc = e
            time.sleep(0.5 * (i + 1))
    raise RuntimeError(f"Failed request {url} → {last_exc}")


def fetch_json(session: requests.Session, url: str) -> Tuple[Optional[Dict[str, Any]], Any]:
    r = request_with_retries(session, url)
    if r.status_code != 200:
        return None, r.status_code
    try:
        return r.json(), 200
    except Exception:
        return None, "json_decode_error"


def download_binary(session: requests.Session, url: str, out: Path) -> Any:
    r = request_with_retries(session, url)
    if r.status_code != 200:
        return r.status_code
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(r.content)
    return 200


# ==========================================================
# HELPERS
# ==========================================================

def extract_year(url: str) -> str:
    parts = urlparse(url).path.split("/")
    for p in parts:
        if p.isdigit() and len(p) == 4:
            return p
    return str(datetime.utcnow().year)


def normalize_id(entry: Dict[str, Any], url: str) -> str:
    if entry.get("id"):
        return entry["id"]
    return Path(urlparse(url).path).stem


def parse_entries(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    return feed.get("feed", {}).get("entry", [])


def extract_links(entry: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns: (hash_url, signature_url)
    """
    hash_url = None
    sig_url = None
    for l in entry.get("link", []):
        if l.get("rel") == "hash":
            hash_url = l.get("href")
        elif l.get("rel") == "signature":
            sig_url = l.get("href")
    return hash_url, sig_url


# ==========================================================
# CORE — TIMESTAMP FIRST
# ==========================================================

def mirror_feed(feed_name: str, feed_url: str, base_dir: Path, session: requests.Session):
    print(f"\n===== FEED: {feed_name} =====")

    feed_obj, status = fetch_json(session, feed_url)
    if status != 200 or not feed_obj:
        print(f"[!] feed error: {status}")
        return

    feed_index = base_dir / "_feeds" / f"{feed_name}.json"

    # optional: skip entire run if feed unchanged
    if not json_should_update(feed_index, feed_obj):
        print("Feed unchanged → skipping.")
        return

    save_json(feed_index, feed_obj)
    entries = parse_entries(feed_obj)
    print("Entries:", len(entries))

    new = updated = skipped = errors = sigs = hashes = 0

    for idx, entry in enumerate(entries, 1):
        src = entry.get("content", {}).get("src")
        if not src:
            continue

        year = extract_year(src)
        adv_id = normalize_id(entry, src)

        out_file = base_dir / year / feed_name / f"{adv_id}.json"
        sha_file = out_file.with_suffix(".json.sha512")
        sig_file = out_file.with_suffix(".json.asc")

        # meta file stores entry.updated (fast decision)
        meta_file = out_file.with_suffix(".meta")
        remote_updated = entry.get("updated")

        # ==================================================
        # FAST SKIP: timestamp matches
        # ==================================================
        if out_file.exists() and remote_updated:
            local_updated = read_text_safe(meta_file)
            if local_updated == remote_updated:
                skipped += 1
                # keep output style
                print(f"[=] {year}/{feed_name}/{adv_id}")
                continue

        # ==================================================
        # NEW or UPDATED: download JSON
        # ==================================================
        obj, st = fetch_json(session, src)
        if st != 200 or not obj:
            errors += 1
            print(f"[!] {idx}/{len(entries)} {adv_id}: {st}")
            time.sleep(SLEEP_ON_ERROR)
            continue

        if out_file.exists():
            updated += 1
            print(f"[U] {year}/{feed_name}/{adv_id}")
        else:
            new += 1
            print(f"[+] {year}/{feed_name}/{adv_id}")

        save_json(out_file, obj)

        # store updated timestamp for future runs
        if remote_updated:
            write_text_safe(meta_file, remote_updated)

        # ==================================================
        # Download hash & signature (optional but you want them)
        # ==================================================
        hash_url, sig_url = extract_links(entry)

        if hash_url:
            if download_binary(session, hash_url, sha_file) == 200:
                hashes += 1

        if sig_url:
            if download_binary(session, sig_url, sig_file) == 200:
                sigs += 1

    print(
        f"Done: new={new}, updated={updated}, skipped={skipped}, "
        f"errors={errors}, sigs={sigs}, hashes={hashes}"
    )


# ==========================================================
# MAIN
# ==========================================================

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with requests.Session() as session:
        for name, url in FEEDS.items():
            mirror_feed(name, url, OUT_DIR, session)


if __name__ == "__main__":
    main()