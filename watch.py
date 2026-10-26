#!/usr/bin/env python3
"""Citrix Security Bulletin watcher.

One run = one headless page load of the public bulletin list, plus plain HTTP
fetches of individual article pages only when needed. Writes /repo/bulletins.json
and, when a commit is warranted, /state/commit-reason for run.sh to act on.
"""
import datetime as dt
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser

LIST_URL = ("https://support.citrix.com/support-home/topic-article-list"
            "?trendingCategory=20&trendingTopicName=Security%20Bulletin")
ARTICLE_URL = "https://support.citrix.com/external/article/{}"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
LIST_SELECTOR = ".wlk-citrix-article a.wlk-citrix-topic-link"

REPO = os.environ.get("REPO_DIR", "/repo")
STATE = os.environ.get("STATE_DIR", "/state")
OUT = os.path.join(REPO, "bulletins.json")
META = os.path.join(STATE, "meta.json")
HINTS = os.path.join(STATE, "email-hints.json")
REASON = os.path.join(STATE, "commit-reason")

FETCH_GAP = 2.0          # seconds between article fetches
REVALIDATE_EVERY = 24 * 3600
REVALIDATE_NEWEST = 10
HEARTBEAT_EVERY = 24 * 3600 - 30 * 60   # a little under a day so hourly cron always lands

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
CTX_RE = re.compile(r"CTX\d{5,7}")

# Canonical product names. Order matters only for output order.
PRODUCTS = [
    ("NetScaler ADC", r"(?:NetScaler|Citrix) ADC"),
    ("NetScaler Gateway", r"(?:NetScaler|Citrix) Gateway"),
    ("NetScaler Console", r"NetScaler Console|Application Delivery Management"),
    ("NetScaler SDX", r"\bSDX\b"),
    ("NetScaler Agent", r"NetScaler Agent"),
    ("XenServer", r"XenServer"),
    ("Citrix Hypervisor", r"Citrix Hypervisor"),
    ("Citrix Virtual Apps and Desktops", r"Virtual Apps and Desktops|\bCVAD\b"),
    ("Citrix DaaS", r"\bDaaS\b"),
    ("Virtual Delivery Agent", r"Virtual Delivery Agent|\bVDA\b"),
    ("StoreFront", r"StoreFront"),
    ("Citrix Provisioning", r"Citrix Provisioning|Provisioning Services"),
    ("Citrix Session Recording", r"Session Recording"),
    ("Citrix License Server", r"License Server"),
    ("Citrix Secure Private Access", r"Secure Private Access"),
    ("Citrix Endpoint Management", r"Endpoint Management"),
    ("Citrix Endpoint Analysis", r"Endpoint Analysis"),
    ("Citrix SD-WAN", r"SD-WAN"),
    ("Citrix ShareFile", r"ShareFile"),
    ("Citrix UniconOS", r"UniconOS"),
    ("Unicon eLux", r"\beLux\b"),
    ("uberAgent", r"uberAgent"),
]
PLATFORMS = r"(?: for (Windows|Mac|Linux|iOS|Android|HTML5|Chrome(?:OS)?))?"
PLATFORM_PRODUCTS = [
    ("Citrix Workspace app", r"Workspace app" + PLATFORMS),
    ("Citrix Secure Access Client", r"Secure Access Client" + PLATFORMS),
]


def now_iso():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(s):
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def log(*a):
    print(now_iso(), *a, flush=True)


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)


def uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def ctx_num(ctx):
    return int(ctx[3:])


def norm(s):
    s = s.replace("\xa0", " ").replace(" ", " ").replace("​", "")
    return re.sub(r"\s+", " ", s).strip()


def match_products(text):
    found = []
    for name, rx in PRODUCTS:
        if re.search(rx, text, re.I):
            found.append(name)
    for name, rx in PLATFORM_PRODUCTS:
        for m in re.finditer(rx, text, re.I):
            found.append(f"{name} for {m.group(1)}" if m.group(1) else name)
    return uniq(found)


# ---------------------------------------------------------------- list page

def scrape_list():
    """Return [(ctx, title)] in page order from one headless page load."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--disable-dev-shm-usage"])
        try:
            context = browser.new_context(user_agent=UA, locale="en-US",
                                          viewport={"width": 1366, "height": 900})
            page = context.new_page()
            page.goto(LIST_URL, wait_until="domcontentloaded", timeout=60_000)
            page.wait_for_selector(LIST_SELECTOR, timeout=60_000)
            # Wait until the list stops growing.
            last, stable = -1, 0
            for _ in range(20):
                n = page.locator(LIST_SELECTOR).count()
                stable = stable + 1 if n == last else 0
                if stable >= 2:
                    break
                last = n
                page.wait_for_timeout(1000)
            rows = page.eval_on_selector_all(
                LIST_SELECTOR, "els => els.map(a => [a.href, a.textContent])")
        finally:
            browser.close()
    out, seen = [], set()
    for href, text in rows:
        m = CTX_RE.search(href or "")
        title = norm(text or "")
        if m and title and m.group(0) not in seen:
            seen.add(m.group(0))
            out.append((m.group(0), title))
    return out


# ---------------------------------------------------------------- article page

class Blocks(HTMLParser):
    """Flatten HTML into ('h'|'p'|'li', text) and ('table', rows) blocks."""
    KIND = {"h1": "h", "h2": "h", "h3": "h", "h4": "h", "h5": "h", "h6": "h",
            "p": "p", "div": "p", "li": "li"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blocks, self.buf, self.stack = [], [], []
        self.skip = 0
        self.table = self.row = self.cell = None
        self.tdepth = 0

    def flush(self):
        text = norm("".join(self.buf))
        self.buf = []
        if text:
            kind = self.KIND[self.stack[-1]] if self.stack else "p"
            self.blocks.append((kind, text))

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self.skip += 1
        elif tag == "table":
            self.tdepth += 1
            if self.tdepth == 1:
                self.flush()
                self.table = []
        elif self.tdepth == 1 and tag == "tr":
            self.row = []
        elif self.tdepth == 1 and tag in ("td", "th"):
            self.cell = []
        elif tag == "br":
            (self.cell if self.cell is not None else self.buf).append("\n")
        elif tag in self.KIND and self.cell is None:
            self.flush()
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript"):
            self.skip = max(0, self.skip - 1)
        elif tag == "table":
            if self.tdepth == 1 and self.table is not None:
                self.blocks.append(("table", self.table))
                self.table = None
            self.tdepth = max(0, self.tdepth - 1)
        elif self.tdepth == 1 and tag in ("td", "th"):
            if self.row is not None and self.cell is not None:
                self.row.append(norm("".join(self.cell)))
            self.cell = None
        elif self.tdepth == 1 and tag == "tr":
            if self.table is not None and self.row:
                self.table.append(self.row)
            self.row = None
        elif tag in self.KIND and self.cell is None and tag in self.stack:
            self.flush()
            while self.stack and self.stack.pop() != tag:
                pass

    def handle_data(self, data):
        if self.skip:
            return
        (self.cell if self.cell is not None else self.buf).append(data)

    def close(self):
        super().close()
        self.flush()


DATE_FORMATS = ("%Y-%m-%d", "%B %d, %Y", "%b %d, %Y", "%d %B %Y", "%m/%d/%Y")


def to_date(s):
    s = norm(s).rstrip(".")
    m = re.search(r"\d{4}-\d{2}-\d{2}", s)
    if m:
        s = m.group(0)
    for f in DATE_FORMATS:
        try:
            return dt.datetime.strptime(s, f).date().isoformat()
        except ValueError:
            pass
    return None


# Section titles. Some bulletins (XenServer) put these in <p> instead of <hN>.
HEADING_RX = re.compile(
    r"^(Description of Problem|Affected Versions|What Customers Should Do|What Citrix is Doing|"
    r"Mitigating Factors|Obtaining Support on This Issue|Subscribe to Receive Alerts|"
    r"Reporting Security Vulnerabilities.*|Change ?log|Acknowledge?ments?|Additional Information|"
    r"Steps to determine.*|Disclaimer|Environment|Issue/Introduction|Description|"
    r"Was this article helpful\?)\s*:?$", re.I)


def is_heading(kind, val):
    return kind == "h" or (kind == "p" and len(val) < 90 and HEADING_RX.match(val))


def section_items(blocks, heading_rx):
    """List items under the first heading matching heading_rx. If the section has
    no list, its paragraphs verbatim (XenServer style). Stops at the next heading."""
    items, paras, on = [], [], False
    for kind, val in blocks:
        if kind == "table":
            if on:
                break
            continue
        if not on:
            if re.match(heading_rx + r"\s*:?$", val, re.I):
                on = True
            continue
        if is_heading(kind, val):
            break
        if kind == "li" and not val.endswith(":"):
            items.append(val)
        elif kind == "p" and len(paras) < 3:
            paras.append(val)
    return uniq(items or paras)


def parse_article(raw):
    """Return parsed fields from an article page. Unknowns are None or empty."""
    p = Blocks()
    p.feed(raw)
    p.close()
    blocks = p.blocks
    texts = [v for k, v in blocks if k != "table"]
    tables = [v for k, v in blocks if k == "table"]

    m = re.search(r'"headline":"([^"]+)"', raw)
    title = norm(html.unescape(m.group(1))) if m else None
    m = re.search(r'"articleTypeName":"([^"]+)"', raw)
    article_type = m.group(1) if m else None

    severity = None
    for t in texts:
        m = re.match(r"Severity\s*[-–:]\s*([A-Za-z]+)", t)
        if m:
            severity = m.group(1).capitalize()
            break

    cvss, pre, table_cves = {}, {}, []
    products_impacted = []
    changelog = []
    for rows in tables:
        if not rows:
            continue
        head = [c.lower() for c in rows[0]]
        if any("cve" in c for c in head):
            ci = next(i for i, c in enumerate(head) if "cve" in c)
            pi = next((i for i, c in enumerate(head) if "pre-condition" in c or "precondition" in c), None)
            si = next((i for i, c in enumerate(head) if "cvss" in c), None)
            for r in rows[1:]:
                if ci >= len(r):
                    continue
                ids = uniq(CVE_RE.findall(r[ci]))
                table_cves += ids
                score_src = r[si] if si is not None and si < len(r) else " ".join(r)
                sm = re.search(r"Base Score:?\s*([0-9]{1,2}(?:\.[0-9])?)", score_src)
                for cve in ids:
                    if sm:
                        cvss[cve] = float(sm.group(1))
                    if pi is not None and pi < len(r) and r[pi]:
                        pre[cve] = r[pi]
        elif "product" in head and "status" in head:
            pi, si = head.index("product"), head.index("status")
            for r in rows[1:]:
                if max(pi, si) < len(r) and r[si].lower().startswith("impacted"):
                    products_impacted += match_products(r[pi]) or [r[pi]]
        else:
            ds = [to_date(r[0]) for r in rows if r]
            if ds and all(ds):
                changelog = ds

    if changelog:
        published, updated = min(changelog), max(changelog)
    else:
        def json_date(key):
            m = re.search(r'"%s":"(\d{2})-(\d{2})-(\d{4})' % key, raw)
            return f"{m.group(3)}-{m.group(1)}-{m.group(2)}" if m else None
        published, updated = json_date("datePublished"), json_date("dateModified")

    body = " ".join(texts)
    exploited = None
    for t in texts:
        for s in re.split(r"(?<=\.)\s+", t):
            if re.search(r"\bexploit(?:s|ed|ation)?\b", s, re.I) and \
                    re.search(r"observed|in the wild|aware|known|reported", s, re.I):
                exploited = s
                break
        if exploited:
            break

    products = match_products(title or "") if title else []
    products = uniq(products + products_impacted)
    if not products:
        for t in texts:
            if re.search(r"\bare affected\b|\bis affected\b", t):
                products = match_products(t)
                if products:
                    break

    return {
        "title": title,
        "articleType": article_type,
        "cves": uniq(CVE_RE.findall(title or "") + table_cves + CVE_RE.findall(body)),
        "products": products,
        "published": published,
        "updated": updated,
        "details": {
            "severity": severity,
            "cvss": cvss,
            "affected": section_items(blocks, r"Affected Versions\b"),
            "fixed": section_items(blocks, r"What Customers Should Do\b"),
            "preconditions": pre,
            "exploited": exploited,
        },
    }


def fetch_article(ctx, etag=None):
    """Return (status, body, etag). status 304 means unchanged."""
    req = urllib.request.Request(ARTICLE_URL.format(ctx), headers={
        "User-Agent": UA, "Accept": "text/html", "Accept-Language": "en-US,en;q=0.9"})
    if etag:
        req.add_header("If-None-Match", etag)
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers.get("ETag")
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return 304, None, etag
        raise


# ---------------------------------------------------------------- run

def empty_details():
    return {"severity": None, "cvss": {}, "affected": [], "fixed": [],
            "preconditions": {}, "exploited": None}


def build(ctx, title, art, first_seen):
    title = title or (art or {}).get("title") or ctx
    b = {
        "ctx": ctx,
        "title": title,
        "url": ARTICLE_URL.format(ctx),
        "cves": uniq(CVE_RE.findall(title) + ((art or {}).get("cves") or [])),
        "products": uniq(match_products(title) + ((art or {}).get("products") or [])),
        "published": (art or {}).get("published"),
        "updated": (art or {}).get("updated"),
        "firstSeen": first_seen,
        "details": (art or {}).get("details") or empty_details(),
    }
    return b


def sort_key(b):
    return (b.get("published") or "0000-00-00", ctx_num(b["ctx"]))


def main():
    os.makedirs(STATE, exist_ok=True)
    run_at = now_iso()
    prev = load_json(OUT, None) or {}
    prev_bulletins = prev.get("bulletins") or []
    prev_map = {b["ctx"]: b for b in prev_bulletins}
    meta = load_json(META, {})
    etags = meta.setdefault("etags", {})
    pending = set(meta.get("pendingDetails", []))
    email_sourced = set(meta.get("emailSourced", []))
    hints_done = meta.setdefault("hintsDone", {})
    hints = (load_json(HINTS, {}) or {}).get("hints", {})

    ok, error, listing = True, "", []
    try:
        listing = scrape_list()
        if not listing:
            ok, error = False, "list page loaded but zero bulletins parsed (site layout may have changed)"
    except Exception as e:  # noqa: BLE001  any failure is reported in the feed
        ok, error = False, f"list page load failed: {type(e).__name__}: {str(e).splitlines()[0][:300]}"
    log(f"list: ok={ok} items={len(listing)} {error}")

    if ok:
        listed = {c: t for c, t in listing}
        want = {}   # ctx -> reason
        for ctx, title in listing:
            b = prev_map.get(ctx)
            if b is None:
                want[ctx] = "new"
            elif b["title"] != title:
                want[ctx] = "title changed"
            elif ctx in pending:
                want[ctx] = "retry"
        for ctx, received in hints.items():
            if CTX_RE.fullmatch(ctx) and hints_done.get(ctx) != received:
                want.setdefault(ctx, "email alert")
        last_rv = parse_iso(meta.get("lastRevalidate", ""))
        if not last_rv or (dt.datetime.now(dt.timezone.utc) - last_rv).total_seconds() >= REVALIDATE_EVERY:
            newest = sorted(prev_bulletins, key=sort_key, reverse=True)[:REVALIDATE_NEWEST]
            for b in newest:
                want.setdefault(b["ctx"], "daily revalidate")
            meta["lastRevalidate"] = run_at

        fetched = {}
        for i, (ctx, why) in enumerate(want.items()):
            if i:
                time.sleep(FETCH_GAP)
            etag = etags.get(ctx) if ctx in prev_map and why != "retry" else None
            try:
                status, body, new_etag = fetch_article(ctx, etag)
            except Exception as e:  # noqa: BLE001
                log(f"article {ctx} ({why}): fetch failed: {e}")
                pending.add(ctx)
                continue
            if why == "email alert":
                hints_done[ctx] = hints[ctx]
            if status == 304:
                log(f"article {ctx} ({why}): 304 unchanged")
                continue
            art = parse_article(body)
            if new_etag:
                etags[ctx] = new_etag
            pending.discard(ctx)
            if ctx not in listed and ctx not in prev_map:
                if (art.get("articleType") or "").lower() != "security bulletin":
                    log(f"article {ctx} ({why}): not a Security Bulletin ({art.get('articleType')}), ignored")
                    continue
                email_sourced.add(ctx)
            fetched[ctx] = art
            log(f"article {ctx} ({why}): parsed, updated={art['updated']} cves={len(art['cves'])}")

        out_map = {}
        for ctx, title in listing:
            out_map[ctx] = (title, None)
        for ctx in email_sourced:
            if ctx not in out_map and (ctx in prev_map or ctx in fetched):
                out_map[ctx] = (None, None)
        bulletins = []
        for ctx, (title, _) in out_map.items():
            old = prev_map.get(ctx)
            first_seen = old["firstSeen"] if old else run_at
            if ctx in fetched:
                b = build(ctx, title or (old or {}).get("title"), fetched[ctx], first_seen)
            elif old:
                b = dict(old)
                if title and title != old["title"]:
                    b["title"] = title
                    b["cves"] = uniq(CVE_RE.findall(title) + old["cves"])
                    b["products"] = uniq(match_products(title) + old["products"])
            else:
                b = build(ctx, title, None, first_seen)
                pending.add(ctx)
            bulletins.append(b)
        bulletins.sort(key=sort_key, reverse=True)
        email_sourced &= {b["ctx"] for b in bulletins}
        last_ok = run_at
    else:
        bulletins = prev_bulletins
        last_ok = prev.get("lastOk", "")

    out = {
        "schema": 1,
        "lastRun": run_at,
        "lastOk": last_ok,
        "ok": ok,
        "error": error,
        "source": LIST_URL,
        "count": len(bulletins),
        "bulletins": bulletins,
    }

    reason = ""
    if not prev:
        reason = "initial"
    elif bulletins != prev_bulletins:
        reason = "bulletins changed"
    elif ok != prev.get("ok") or error != prev.get("error"):
        reason = "status " + ("ok" if ok else "error")
    else:
        last_commit = parse_iso(meta.get("lastCommit", ""))
        if not last_commit or (dt.datetime.now(dt.timezone.utc) - last_commit).total_seconds() >= HEARTBEAT_EVERY:
            reason = "heartbeat"

    save_json(OUT, out)
    meta["pendingDetails"] = sorted(pending)
    meta["emailSourced"] = sorted(email_sourced)
    if reason:
        meta["lastCommit"] = run_at
        with open(REASON, "w", encoding="utf-8") as f:
            f.write(reason + "\n")
    save_json(META, meta)
    log(f"done: ok={ok} count={len(bulletins)} commit={reason or 'no'}")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
