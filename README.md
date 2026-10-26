# citrix-bulletin-watch

An hourly mirror of the public [Citrix Security Bulletin list](https://support.citrix.com/support-home/topic-article-list?trendingCategory=20&trendingTopicName=Security%20Bulletin) as a single JSON file:

**https://raw.githubusercontent.com/tduplantis/citrix-bulletin-watch/main/bulletins.json**

Everything here is public information taken from support.citrix.com. This repo is not affiliated with Citrix or Cloud Software Group.

## How it works

Each run:

1. Loads the bulletin list page once in headless Chromium (Playwright), as a normal visitor would. The page is a JavaScript app, so plain HTTP does not work there. No API tokens are obtained or replayed.
2. Fetches a bulletin's own article page (`https://support.citrix.com/external/article/<CTX>`, server-rendered) only when:
   * the bulletin is new, or its title changed on the list
   * a "New or Updated Article" alert for it arrived (optional hints file, see below)
   * once a day, for the 10 newest bulletins, as a conditional request (`If-None-Match`). An unchanged page answers `304` with no body.
3. Writes `bulletins.json`, then commits and pushes only when the bulletins change, when `ok`/`error` changes, or once a day as a heartbeat.

Article fetches are spaced 2 seconds apart. The very first run backfills every listed bulletin once.

If the list page cannot be loaded, or loads but yields zero bulletins (the site changed), the run sets `ok: false` with an `error`, keeps the previous bulletins unchanged, and still pushes so consumers can see the failure.

## Format

```json
{
  "schema": 1,
  "lastRun": "<UTC ISO>",
  "lastOk": "<UTC ISO>",
  "ok": true,
  "error": "",
  "source": "<list page url>",
  "count": 41,
  "bulletins": [
    {
      "ctx": "CTX697191",
      "title": "...",
      "url": "https://support.citrix.com/external/article/CTX697191",
      "cves": ["CVE-..."],
      "products": ["NetScaler ADC", "NetScaler Gateway"],
      "published": "YYYY-MM-DD",
      "updated": "YYYY-MM-DD",
      "firstSeen": "<UTC ISO>",
      "details": {
        "severity": "...",
        "cvss": { "CVE-...": 9.5 },
        "affected": ["..."],
        "fixed": ["..."],
        "preconditions": { "CVE-...": "..." },
        "exploited": "text or null"
      }
    }
  ]
}
```

Field notes:

| Field | Meaning |
|---|---|
| `lastRun` | Last run time. Only updated in git on a commit, so at least daily. |
| `lastOk` | Last run that loaded the list successfully. |
| `ctx` | Key. Citrix article number. |
| `bulletins` | Newest first, by `published`, then by CTX number. |
| `cves`, `products` | Parsed from the title and the article. Products use canonical names (for example `NetScaler ADC`, `Citrix Workspace app for Windows`). |
| `published`, `updated` | First and last dates in the article's changelog. `null` if the article has not been fetched or has no dates. |
| `firstSeen` | When this watcher first saw the bulletin. On the first run every bulletin gets that run's time. |
| `details.severity` | From the article's "Severity" line, or `null`. |
| `details.cvss` | CVSS base score per CVE from the article's CVE table. Empty if the article has none (XenServer updates usually don't). |
| `details.affected`, `details.fixed` | The article's "Affected Versions" and "What Customers Should Do" items. If a section is prose rather than a list, its paragraphs verbatim. |
| `details.preconditions` | The "Pre-conditions" column of the CVE table, per CVE. |
| `details.exploited` | The article's own sentence about exploitation (for example "Exploits of CVE-... have been observed."), or `null`. |

Nothing is guessed. Anything the article does not state is `null` or empty.

## Running it

Requirements: Linux with Docker, git, cron, and an SSH deploy key with write access to this repo.

Layout on the host:

```
~/citrix-bulletin-watch/
  repo/    this repository (clone over SSH)
  state/   ETags, pending retries, optional email-hints.json (never committed)
  logs/    cbw-YYYY-MM-DD.log, 14 days kept
```

Run once by hand (prints to the terminal and the log):

```bash
~/citrix-bulletin-watch/repo/run.sh
```

Hourly cron entry (pick your own minute):

```
37 * * * * $HOME/citrix-bulletin-watch/repo/run.sh
```

`run.sh` builds the image from `Dockerfile` (based on `mcr.microsoft.com/playwright/python`) the first time and whenever `watch.py` or the `Dockerfile` changes. It uses `flock`, so overlapping runs are skipped.

### Optional alert hints

If you receive Citrix "Notification Alert for New or Updated Article" emails, something outside this repo can drop the CTX numbers into `state/email-hints.json`:

```json
{ "updated": "<UTC ISO>", "hints": { "CTX697263": "<alert received, UTC ISO>" } }
```

Each new `(CTX, received)` pair triggers one conditional fetch of that article. A hinted CTX that is a Security Bulletin but not yet on the list page is added to `bulletins` (alerts often arrive before the list updates). Only CTX numbers are read. No email content is used or stored.
