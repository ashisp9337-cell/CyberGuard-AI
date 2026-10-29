r"""Step 1 of the network-traffic training: LOOK at what the official dataset sites offer - nothing is downloaded.

Reads only the small HTML index pages of the two official download sites and prints every data file with its size,
so the exact files can be chosen and pinned before anything big is downloaded:
  * the corrected CIC-IDS2017 (Engelen et al., KU Leuven / DistriNet, WTMC 2021)
  * the original CIC-IDS2017 (Canadian Institute for Cybersecurity, UNB)

Writes no files, runs nothing it reads, needs no keys. Run from the backend folder:
    python -I app\ml\training\find_network_data.py
(run it as a file: with -I, "python -m app..." cannot find the project folder; this script imports nothing from it)
"""
import html.parser
import sys
import urllib.error
import urllib.parse
import urllib.request

STARTS = [
    "https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html",
    "https://downloads.distrinet-research.be/WTMC2021/",
    "http://cicresearch.ca/CICDataset/CIC-IDS-2017/",
]
DATA_EXT = (".zip", ".csv", ".parquet", ".gz", ".tgz", ".tar", ".7z", ".rar", ".xz", ".bz2", ".pcap", ".md5", ".sha256",
            ".txt", ".md")
MAX_PAGES = 120          # hard stop: never crawls more than this many small index pages
TIMEOUT = 30
UA = {"User-Agent": "CyberGuard-dataset-check/1.0 (student hackathon project; reads index pages only)"}


class Links(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href and not href.startswith(("#", "mailto:", "javascript:", "?")):
                self.links.append(href)


def get_page(url: str) -> str | None:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=TIMEOUT) as r:
            if "html" not in (r.headers.get("Content-Type") or "html"):
                return None
            return r.read(2_000_000).decode("utf-8", errors="replace")      # index pages are small; cap at 2 MB
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"  ! could not open {url}: {exc}")
        return None


def size_of(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers=UA, method="HEAD")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            n = r.headers.get("Content-Length")
        return f"{int(n) / 1e6:,.1f} MB" if n else "size unknown"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return "size unknown"


def main() -> int:
    seen_pages, files = set(), {}
    queue = [(u, u if u.endswith("/") else u.rsplit("/", 1)[0] + "/") for u in STARTS]
    while queue and len(seen_pages) < MAX_PAGES:
        url, root = queue.pop(0)
        if url in seen_pages:
            continue
        seen_pages.add(url)
        print(f"reading {url}")
        page = get_page(url)
        if page is None:
            continue
        p = Links()
        p.feed(page)
        for href in p.links:
            full = urllib.parse.urljoin(url, href)
            low = urllib.parse.urlparse(full).path.lower()
            if low.endswith(DATA_EXT):
                files.setdefault(full, None)
            elif full.endswith("/") and full.startswith(root) and full != url and full not in seen_pages:
                queue.append((full, root))                       # sub-folder of the same site folder only
            elif "downloads.distrinet-research.be" in full and full.endswith("/"):
                queue.append((full, full))                       # the info page links to the download folder
    print(f"\nFound {len(files)} file(s) on {len(seen_pages)} page(s). Sizes (HEAD request only, nothing downloaded):")
    for f in sorted(files):
        print(f"  {size_of(f):>14}  {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
