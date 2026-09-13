#!/usr/bin/env python3
"""GDELT DOC 2.0 lookup. Free, keyless; indexes news actors, so a private individual rarely
appears — country-level context, not evidence."""
import json
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.gdeltproject.org/api/v2/doc/doc"
UA = "Mozilla/5.0 (X11; Linux x86_64) kargu-osint/1.0"


def search(query, timespan="7d", maxrecords=50, timeout=25, proxies=None):
    """Return {"articles": [...], "timespan": ..} or {"error": ..}. Never raises."""
    q = urllib.parse.urlencode({"query": query, "mode": "artlist", "maxrecords": maxrecords,
                                "format": "json", "timespan": timespan, "sort": "datedesc"})
    req = urllib.request.Request(f"{API}?{q}", headers={"User-Agent": UA})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies)) if proxies \
        else urllib.request.build_opener()
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            return {"error": "GDELT rate limit: one query every 5 seconds", "status": 429, "articles": []}
        return {"error": f"GDELT answered HTTP {e.code}", "status": e.code, "articles": []}
    except json.JSONDecodeError:
        # GDELT answers bad queries with an HTML page, not JSON.
        return {"error": "GDELT returned no JSON (malformed query)", "articles": []}
    except Exception as e:
        return {"error": f"GDELT unreachable ({type(e).__name__})", "articles": []}
    arts = []
    for a in data.get("articles") or []:
        arts.append({"url": a.get("url"), "title": a.get("title"), "seendate": a.get("seendate"),
                     "domain": a.get("domain"), "language": a.get("language"),
                     "sourcecountry": a.get("sourcecountry")})
    return {"articles": arts, "timespan": timespan, "query": query}


if __name__ == "__main__":
    import sys
    print(json.dumps(search(" ".join(sys.argv[1:]) or '"example"'), indent=1, ensure_ascii=False))
