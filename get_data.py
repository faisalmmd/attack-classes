import os
import re
import csv
import time
import json
import hashlib
import random
import argparse
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urljoin, urldefrag, unquote

import requests
from bs4 import BeautifulSoup


# ----------------------------
# Config
# ----------------------------
ALLOWED_EXTS = {".css", ".js", ".xml"}   # only download these

DEFAULT_TIMEOUT = 30
REQ_RETRIES_FIRST_PASS = 2               # light retries during main pass
REQ_RETRIES_END_PASS = 4                 # heavier retries at end
BASE_DELAY_SEC = 1.5
JITTER_SEC = 1.0

FAILURE_LOG = "failed_downloads.csv"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)

# Only extracting refs that commonly point to css/js/xml:
RESOURCE_ATTRS = [
    ("script", "src"),
    ("link", "href"),
]

CSS_IMPORT_RE = re.compile(r"""@import\s+(?:url\()?['"]([^'"]+)['"]\)?""", re.IGNORECASE)
CSS_URL_RE = re.compile(r"""url\(\s*(['"]?)(.*?)\1\s*\)""", re.IGNORECASE)


# ----------------------------
# Failure items
# ----------------------------
@dataclass
class FailureItem:
    row_id: str
    kind: str               # "page" or "resource"
    timestamp: str
    original_url: str
    resource_url: str       # "" for page failures
    reason: str


failures = []


# ----------------------------
# Helpers (sanitization-heavy)
# ----------------------------
def polite_sleep():
    time.sleep(BASE_DELAY_SEC + random.random() * JITTER_SEC)


def safe_component(s: str) -> str:
    """Safe single path component (no slashes)."""
    s = unquote(s or "")
    s = s.replace("\\", "_").replace(":", "_")
    s = s.strip()
    s = re.sub(r"[^\w\-.]", "_", s)
    s = s.strip("_")
    return s or "x"


def parse_wayback_line(line: str):
    """
    Expects full Wayback URL like:
      https://web.archive.org/web/20160120012115/https://www.dmv.ca.gov/portal/dmv
      https://web.archive.org/web/20160120012115id_/https://www.dmv.ca.gov/portal/dmv
    Leading '-' is tolerated.
    Returns: (timestamp, original_url)
    """
    line = line.strip()
    if line.startswith("-"):
        line = line.lstrip("-").strip()

    m = re.search(r"/web/(\d{6,14})(?:[a-z_]{0,6})?/(.*)$", line)
    if not m:
        raise ValueError("Not a valid Wayback URL with /web/<timestamp>/...")

    ts = m.group(1)
    orig = m.group(2).strip()

    if orig.startswith("//"):
        orig = "http:" + orig
    if not urlparse(orig).scheme:
        orig = "http://" + orig

    return ts, orig


def wayback_id_url(timestamp: str, original_url: str) -> str:
    return f"https://web.archive.org/web/{timestamp}id_/{original_url}"


def local_path_for_resource(snapshot_root: Path, resource_url: str) -> Path:
    """
    Always returns a path UNDER snapshot_root (never absolute).
    Organize by resource host to avoid collisions:
      snapshot_root/resources/<resource_host>/<path...>
    """
    p = urlparse(resource_url)
    res_host = safe_component(p.netloc or "nohost")

    path = unquote(p.path or "")
    path = path.lstrip("/")  # CRITICAL: prevent absolute path joins
    if not path or path.endswith("/"):
        path = (path.rstrip("/") + "/index").lstrip("/")

    dir_part = os.path.dirname(path)
    file_part = os.path.basename(path)

    dir_segments = [safe_component(seg) for seg in dir_part.split("/") if seg and seg not in (".", "..")]
    file_part = safe_component(file_part)

    if p.query:
        h = hashlib.sha1(p.query.encode("utf-8")).hexdigest()[:10]
        stem, ext = os.path.splitext(file_part)
        file_part = f"{stem}_{h}{ext or ''}"

    rel = Path("resources") / res_host / Path(*dir_segments) / file_part
    return (snapshot_root / rel).resolve()


def is_allowed_resource(url: str, tag=None) -> bool:
    u = (url or "").strip()
    if not u:
        return False
    low = u.lower()
    if low.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
        return False

    path = urlparse(u).path.lower()
    ext = os.path.splitext(path)[1]
    if ext in ALLOWED_EXTS:
        return True

    # allow XML-ish <link> types even if no .xml extension
    if tag is not None and getattr(tag, "name", "") == "link":
        t = (tag.get("type") or "").lower()
        if "xml" in t or "rss" in t or "atom" in t:
            return True

    return False


def save_bytes(path: Path, data: bytes, overwrite: bool):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        return
    with open(path, "wb") as f:
        f.write(data)


def save_text(path: Path, text: str, overwrite: bool):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        return
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(text)


def write_csv_failure(item: FailureItem):
    file_exists = os.path.exists(FAILURE_LOG)
    with open(FAILURE_LOG, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not file_exists:
            w.writerow(["row_id", "kind", "timestamp", "original_url", "resource_url", "reason"])
        w.writerow([item.row_id, item.kind, item.timestamp, item.original_url, item.resource_url, item.reason])


def http_get_with_retries(session: requests.Session, url: str, retries: int):
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            resp = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            if resp.status_code in (429, 503):
                wait = 5 * attempt + random.random() * 2
                print(f"      [!] {resp.status_code} rate/overload. Sleeping {wait:.1f}s then retry ({attempt}/{retries})")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp
        except Exception as e:
            last_exc = e
            wait = 2 * attempt + random.random()
            print(f"      [!] Request failed ({attempt}/{retries}): {e} -> sleep {wait:.1f}s")
            time.sleep(wait)
    raise last_exc


def extract_css_extra_urls(css_text: str, base_url: str):
    """
    Extract only allowed URLs from CSS (mostly @import of other CSS).
    """
    found = set()

    for m in CSS_IMPORT_RE.finditer(css_text):
        u = m.group(1).strip()
        if not u:
            continue
        abs_u = urljoin(base_url, u)
        abs_u, _ = urldefrag(abs_u)
        if is_allowed_resource(abs_u):
            found.add(abs_u)

    for m in CSS_URL_RE.finditer(css_text):
        u = (m.group(2) or "").strip()
        if not u:
            continue
        abs_u = urljoin(base_url, u)
        abs_u, _ = urldefrag(abs_u)
        if is_allowed_resource(abs_u):
            found.add(abs_u)

    return found


def rewrite_html_refs(soup: BeautifulSoup, base_href: str, url_to_local_rel: dict):
    for tag_name, attr in RESOURCE_ATTRS:
        for tag in soup.find_all(tag_name):
            val = (tag.get(attr) or "").strip()
            if not val:
                continue
            abs_u = urljoin(base_href, val)
            abs_u, _ = urldefrag(abs_u)
            if abs_u in url_to_local_rel:
                tag[attr] = url_to_local_rel[abs_u]
    return soup


def read_lines(txt_path: str):
    lines = []
    with open(txt_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("-"):
                s = s.lstrip("-").strip()
            lines.append(s)
    return lines


# ----------------------------
# Core per-page download
# ----------------------------
def download_page_and_resources(row_id: str, timestamp: str, original_url: str, out_base: Path, request_retries: int, force: bool):
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    host = urlparse(original_url).netloc or "nohost"
    host_dir = safe_component(host)

    # REQUIRED OUTPUT STRUCTURE: website/snapshot/{files}
    snapshot_root = (out_base / host_dir / timestamp).resolve()
    snapshot_root.mkdir(parents=True, exist_ok=True)

    html_path = snapshot_root / "index.html"
    html_original_path = snapshot_root / "index.original.html"
    meta_path = snapshot_root / "download_meta.json"

    if html_path.exists() and not force:
        print(f"\n[=] ROW {row_id}: {timestamp} :: {original_url}")
        print(f"    -> output dir: {snapshot_root}")
        print(f"    [SKIP] index.html already exists (use --force to re-download)")
        return {
            "skipped": True,
            "resources_found_in_html": 0,
            "allowed_resources_initial": 0,
            "allowed_resources_total_seen": 0,
            "resources_downloaded": 0,
            "resources_skipped_non_allowed": 0,
        }

    print(f"\n[+] ROW {row_id}: {timestamp} :: {original_url}")
    print(f"    -> output dir: {snapshot_root}")
    print(f"    -> html file : index.html")

    # 1) Download main HTML
    main_url = wayback_id_url(timestamp, original_url)
    print(f"    [HTML] GET {main_url}")
    resp = http_get_with_retries(session, main_url, retries=request_retries)
    html_bytes = resp.content
    polite_sleep()

    save_bytes(html_original_path, html_bytes, overwrite=force)

    soup = BeautifulSoup(html_bytes, "html.parser")

    # base href
    base_tag = soup.find("base")
    base_href = base_tag.get("href").strip() if base_tag and base_tag.get("href") else original_url
    base_href = urljoin(original_url, base_href)

    # 2) Extract resource URLs (all), filter allowed
    all_resources = []
    allowed_resources = []

    for tag_name, attr in RESOURCE_ATTRS:
        for tag in soup.find_all(tag_name):
            val = (tag.get(attr) or "").strip()
            if not val:
                continue
            abs_u = urljoin(base_href, val)
            abs_u, _ = urldefrag(abs_u)
            if urlparse(abs_u).scheme not in ("http", "https"):
                continue
            all_resources.append(abs_u)
            if is_allowed_resource(abs_u, tag=tag):
                allowed_resources.append(abs_u)
            else:
                print(f"    [skip] (not css/js/xml) {abs_u}")

    def dedupe(seq):
        seen, out = set(), []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    all_resources = dedupe(all_resources)
    allowed_resources = dedupe(allowed_resources)

    skipped = len(all_resources) - len(allowed_resources)
    print(f"    [*] Resources found in HTML (all): {len(all_resources)}")
    print(f"    [*] Allowed (css/js/xml):         {len(allowed_resources)}")
    if skipped > 0:
        print(f"    [#] Skipped non-allowed:          {skipped}")

    # Map allowed resources to local paths (so HTML can be rewritten)
    url_to_local_rel = {}
    for u in allowed_resources:
        lp = local_path_for_resource(snapshot_root, u)
        url_to_local_rel[u] = lp.relative_to(snapshot_root).as_posix()

    # 3) Download allowed resources (+ allowed discovered from CSS)
    downloaded = set()
    queue = list(allowed_resources)
    total_seen_allowed = len(queue)

    i = 0
    while queue:
        i += 1
        res_url = queue.pop(0)

        if res_url in downloaded:
            continue

        if not is_allowed_resource(res_url):
            # should not happen often, but keep safe
            print(f"    [skip] (not css/js/xml) {res_url}")
            continue

        local_path = local_path_for_resource(snapshot_root, res_url)
        rel_path = local_path.relative_to(snapshot_root).as_posix()
        wb_res_url = wayback_id_url(timestamp, res_url)

        # If file exists and not forcing, skip downloading it
        if local_path.exists() and not force:
            print(f"    [RES {i}/{max(total_seen_allowed, i)}] SKIP exists: {rel_path}")
            downloaded.add(res_url)  # counts as "present"
            continue

        print(f"    [RES {i}/{max(total_seen_allowed, i)}] GET {wb_res_url}")
        try:
            r = http_get_with_retries(session, wb_res_url, retries=request_retries)
            content = r.content
            save_bytes(local_path, content, overwrite=True)  # if we decided to download, overwrite is fine
            downloaded.add(res_url)
            print(f"         -> saved {rel_path} ({len(content)} bytes)")
            polite_sleep()

            # If CSS, parse for more allowed URLs and enqueue them
            if local_path.suffix.lower() == ".css":
                css_text = content.decode("utf-8", errors="ignore")
                extra = extract_css_extra_urls(css_text, base_url=res_url)
                added = 0
                for u in extra:
                    if u not in url_to_local_rel:
                        lp2 = local_path_for_resource(snapshot_root, u)
                        url_to_local_rel[u] = lp2.relative_to(snapshot_root).as_posix()
                    if u not in downloaded and u not in queue:
                        queue.append(u)
                        added += 1
                if added:
                    total_seen_allowed += added
                    print(f"         [CSS] discovered +{added} extra allowed resources")

        except Exception as e:
            reason = str(e)
            print(f"    [!] Resource failed: {res_url} -> {reason}")
            fail = FailureItem(
                row_id=row_id,
                kind="resource",
                timestamp=timestamp,
                original_url=original_url,
                resource_url=res_url,
                reason=reason,
            )
            failures.append(fail)
            write_csv_failure(fail)

    # 4) Rewrite HTML to local refs
    soup = rewrite_html_refs(soup, base_href=base_href, url_to_local_rel=url_to_local_rel)
    save_text(html_path, str(soup), overwrite=True)  # index.html is your canonical output

    meta = {
        "row_id": row_id,
        "timestamp": timestamp,
        "original_url": original_url,
        "wayback_main_url": main_url,
        "resources_found_in_html": len(all_resources),
        "allowed_resources_initial": len(allowed_resources),
        "allowed_resources_total_seen": total_seen_allowed,
        "resources_downloaded_or_present": len(downloaded),
        "resources_skipped_non_allowed": skipped,
        "forced": bool(force),
    }
    save_text(meta_path, json.dumps(meta, indent=2), overwrite=True)

    print(f"    [OK] HTML saved:  {html_path}")
    print(f"    [OK] Meta saved:  {meta_path}")
    print(f"    [SUM] Allowed total seen: {total_seen_allowed} | Downloaded/present: {len(downloaded)} | Failed this snapshot: {sum(1 for f in failures if f.row_id == row_id and f.kind=='resource')}")
    return {
        "skipped": False,
        "resources_found_in_html": len(all_resources),
        "allowed_resources_initial": len(allowed_resources),
        "allowed_resources_total_seen": total_seen_allowed,
        "resources_downloaded": len(downloaded),
        "resources_skipped_non_allowed": skipped,
    }


# ----------------------------
# Retry at end
# ----------------------------
def retry_failures_at_end(out_base: Path, force: bool):
    if not failures:
        print("\n[+] No failures to retry.")
        return

    to_retry = list(failures)
    print(f"\n[+] Retrying failures at end: {len(to_retry)} items (higher retry count)")

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    retried_ok = 0
    retried_fail = 0

    for n, item in enumerate(to_retry, start=1):
        print(f"\n[RETRY {n}/{len(to_retry)}] kind={item.kind} ts={item.timestamp}")
        try:
            if item.kind == "page":
                # Force page retry so it doesn't skip if index exists
                download_page_and_resources(
                    row_id=item.row_id,
                    timestamp=item.timestamp,
                    original_url=item.original_url,
                    out_base=out_base,
                    request_retries=REQ_RETRIES_END_PASS,
                    force=True,
                )
            else:
                host = urlparse(item.original_url).netloc or "nohost"
                host_dir = safe_component(host)
                snapshot_root = (out_base / host_dir / item.timestamp).resolve()
                snapshot_root.mkdir(parents=True, exist_ok=True)

                wb_res_url = wayback_id_url(item.timestamp, item.resource_url)
                local_path = local_path_for_resource(snapshot_root, item.resource_url)
                rel_path = local_path.relative_to(snapshot_root).as_posix()

                # Respect force for resource retry too:
                if local_path.exists() and not force:
                    print(f"    [RES RETRY] SKIP exists: {rel_path}")
                    retried_ok += 1
                    continue

                print(f"    [RES RETRY] GET {wb_res_url}")
                r = http_get_with_retries(session, wb_res_url, retries=REQ_RETRIES_END_PASS)
                save_bytes(local_path, r.content, overwrite=True)
                print(f"         -> saved {rel_path} ({len(r.content)} bytes)")
                polite_sleep()

            retried_ok += 1

        except Exception as e:
            retried_fail += 1
            reason = str(e)
            print(f"    [!] Retry still failed: {reason}")
            again = FailureItem(
                row_id=item.row_id,
                kind=item.kind,
                timestamp=item.timestamp,
                original_url=item.original_url,
                resource_url=item.resource_url,
                reason=f"RETRY_FAILED: {reason}",
            )
            write_csv_failure(again)

    print(f"\n[+] Retry summary: succeeded={retried_ok}, still_failed={retried_fail}")


# ----------------------------
# Main
# ----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="txt file with one Wayback URL per line")
    ap.add_argument("--output", required=True, help="output directory")
    ap.add_argument("--force", action="store_true", help="force re-download even if index.html exists")
    args = ap.parse_args()

    out_base = Path(args.output).resolve()
    out_base.mkdir(parents=True, exist_ok=True)

    urls = read_lines(args.input)
    total = len(urls)
    print(f"[+] Loaded {total} URLs from {args.input}")
    print(f"[+] Output base: {out_base}")
    print(f"[+] Force: {args.force}")

    totals = {
        "pages_ok": 0,
        "pages_failed": 0,
        "pages_skipped": 0,
        "resources_found_in_html": 0,
        "allowed_initial": 0,
        "allowed_total_seen": 0,
        "downloaded": 0,
        "skipped_non_allowed": 0,
    }

    for idx, line in enumerate(urls, start=1):
        row_id = str(idx)
        print(f"\n=== SNAPSHOT {idx}/{total} ===")
        try:
            ts, orig = parse_wayback_line(line)
            meta = download_page_and_resources(
                row_id=row_id,
                timestamp=ts,
                original_url=orig,
                out_base=out_base,
                request_retries=REQ_RETRIES_FIRST_PASS,
                force=args.force,
            )
            if meta.get("skipped"):
                totals["pages_skipped"] += 1
                continue

            totals["pages_ok"] += 1
            totals["resources_found_in_html"] += meta["resources_found_in_html"]
            totals["allowed_initial"] += meta["allowed_resources_initial"]
            totals["allowed_total_seen"] += meta["allowed_resources_total_seen"]
            totals["downloaded"] += meta["resources_downloaded"]
            totals["skipped_non_allowed"] += meta["resources_skipped_non_allowed"]

        except Exception as e:
            reason = str(e)
            print(f"[!] Snapshot failed: {reason}")
            ts, orig = "", ""
            try:
                ts, orig = parse_wayback_line(line)
            except Exception:
                pass
            item = FailureItem(row_id=row_id, kind="page", timestamp=ts, original_url=orig, resource_url="", reason=reason)
            failures.append(item)
            write_csv_failure(item)
            totals["pages_failed"] += 1

    print("\n================ SUMMARY (before end retries) ================")
    print(f"Pages OK: {totals['pages_ok']} | Skipped: {totals['pages_skipped']} | Failed: {totals['pages_failed']}")
    print(f"Resources found in HTML (all): {totals['resources_found_in_html']}")
    print(f"Allowed initial (css/js/xml):  {totals['allowed_initial']}")
    print(f"Allowed total seen (with CSS discovers): {totals['allowed_total_seen']}")
    print(f"Downloaded/present (css/js/xml): {totals['downloaded']}")
    print(f"Skipped non-allowed:           {totals['skipped_non_allowed']}")
    print(f"Failures recorded:             {len(failures)}")
    print("=============================================================")

    retry_failures_at_end(out_base, force=args.force)


if __name__ == "__main__":
    main()


# Run examples:

# python3 get_data.py --input urls.txt --output snapshot_downloads

# python3 get_data.py --input urls.txt --output snapshot_downloads --force
