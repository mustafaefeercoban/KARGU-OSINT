#!/usr/bin/env python3
"""Sentinel-2 quicklook for a point, via the Copernicus Data Space STAC API.

Needs COPERNICUS_CLIENT_ID / COPERNICUS_CLIENT_SECRET in config/.env (free account,
dataspace.copernicus.eu). 10 m resolution: terrain and buildings, never people.

    python3 feeds/sentinel.py <lat> <lon> [days]
"""
import datetime
import json
import os
import pathlib
import sys
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOKEN_URL = "https://identity.dataspace.copernicus.eu/auth/realms/CDSE/protocol/openid-connect/token"
STAC = "https://catalogue.dataspace.copernicus.eu/stac/search"


def _env():
    env = {}
    p = ROOT / "config" / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if s and not s.startswith("#") and "=" in s:
                k, v = s.split("=", 1)
                env[k.strip().upper()] = v.strip().strip('"').strip("'")
    env.update({k: v for k, v in os.environ.items() if k.startswith("COPERNICUS_")})
    return env


def _token(cid, secret):
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": cid,
                                   "client_secret": secret}).encode()
    with urllib.request.urlopen(urllib.request.Request(TOKEN_URL, data=body), timeout=25) as r:
        return json.load(r)["access_token"]


def quicklooks(lat, lon, days=30, limit=5):
    """Return {"items": [...]} or {"skipped"/"error": ..}. Never raises."""
    env = _env()
    cid, sec = env.get("COPERNICUS_CLIENT_ID"), env.get("COPERNICUS_CLIENT_SECRET")
    if not (cid and sec):
        return {"skipped": "COPERNICUS_CLIENT_ID / COPERNICUS_CLIENT_SECRET not set", "items": []}
    try:
        tok = _token(cid, sec)
        since = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).strftime("%Y-%m-%dT00:00:00Z")
        d = 0.05
        q = {"collections": ["SENTINEL-2"], "bbox": [lon - d, lat - d, lon + d, lat + d],
             "datetime": f"{since}/..", "limit": limit,
             "query": {"cloudCover": {"lt": 40}}}
        req = urllib.request.Request(STAC, data=json.dumps(q).encode(),
                                     headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=40) as r:
            feats = json.load(r).get("features") or []
        items = []
        for f in feats:
            a = f.get("assets") or {}
            ql = (a.get("QUICKLOOK") or a.get("quicklook") or a.get("thumbnail") or {}).get("href")
            items.append({"id": f.get("id"), "datetime": (f.get("properties") or {}).get("datetime"),
                          "cloud": (f.get("properties") or {}).get("cloudCover"), "quicklook": ql})
        return {"items": items, "bbox_deg": d}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:120]}", "items": []}


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(2)
    print(json.dumps(quicklooks(float(sys.argv[1]), float(sys.argv[2]),
                                int(sys.argv[3]) if len(sys.argv) > 3 else 30), indent=1))
