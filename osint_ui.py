#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KARGU-OSINT · local web UI (English).

Same intake questions as the console wizard, but as a form; runs the scan in the
background, streams the log live, and links straight to the readable HTML report.

Every scan produces ONE folder under cases/: <case>.txt (profile + findings), <case>.html
(the report) and <case>.json (the export the fusion dashboard reads).

Usage:  kargu-ui [--port N] [--no-browser]
Binds to localhost only and opens the browser automatically.
"""
import argparse, datetime, html, os, pathlib, re, secrets, socket, subprocess, sys, threading, time, uuid
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from osint_wizard import FIELDS, ML_PY, slugify, build_profile_text  # noqa: E402

from flask import Flask, request, redirect, url_for, jsonify, send_file, abort

HOME = pathlib.Path.home()
# Same anchor as osint_run.py (this file's directory, OSINT_HOME overrides) so UI and scans agree on cases/.
OSINT = pathlib.Path(os.environ.get("OSINT_HOME") or pathlib.Path(__file__).resolve().parent)
CASES = OSINT / "cases"
CASES.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
JOBS = {}          # id -> {"log": [...], "status": ..., "case": ..., "report": ...}

# Per-process CSRF token: without it any page open in the same browser could submit a scan of
# an attacker-chosen target from this machine. Loopback binding does not prevent that.
CSRF_TOKEN = secrets.token_urlsafe(32)
LOCAL_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}

# Loopback binding keeps out other machines, not other local users or processes; a per-launch
# token (carried by the auto-opened URL, then a cookie) keeps past reports private to the launcher.
ACCESS_TOKEN = secrets.token_urlsafe(24)
ACCESS_COOKIE = "osint_access"

@app.before_request
def _require_access_token():
    if secrets.compare_digest(request.cookies.get(ACCESS_COOKIE) or "", ACCESS_TOKEN):
        return None
    t = request.args.get("t") or ""
    if t and secrets.compare_digest(t, ACCESS_TOKEN):
        resp = redirect(request.path or "/")
        resp.set_cookie(ACCESS_COOKIE, ACCESS_TOKEN, httponly=True, samesite="Strict")
        return resp
    abort(403, "This KARGU-OSINT UI is private to the terminal that started it. Open the "
               "link printed there — it carries this process's access token.")

def _same_origin_ok(req):
    """Reject cross-site submissions and DNS-rebinding hosts before anything is launched."""
    if not secrets.compare_digest(req.form.get("csrf") or "", CSRF_TOKEN):
        return False
    # A hostile domain resolving to 127.0.0.1 (DNS rebinding) would otherwise pass as same-origin.
    if (req.host or "").rsplit(":", 1)[0] not in LOCAL_NAMES:
        return False
    for hdr in ("Origin", "Referer"):
        v = req.headers.get(hdr)
        if v and (urlparse(v).hostname or "") not in LOCAL_NAMES:
            return False
    return True

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1b1b19;--mut:#6b6b66;--line:#e3e3de;--accent:#b5502a;--good:#2f7d4f;--bad:#b3352c}
@media (prefers-color-scheme:dark){:root{--bg:#16171a;--card:#1e2024;--fg:#e9e9e6;--mut:#9a9a94;--line:#2e3136;--accent:#e08256;--good:#59b37f;--bad:#e0705f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:30px 20px 70px}
h1{font-size:24px;margin:0 0 4px} h2{font-size:16px;margin:28px 0 10px;padding-bottom:7px;border-bottom:1px solid var(--line)}
.sub{color:var(--mut);font-size:13px;margin-bottom:20px}
.field{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:12px}
.field label{display:block;font-weight:600;margin-bottom:2px}
.field .hint{color:var(--mut);font-size:12.5px;margin-bottom:8px}
input[type=text]{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font-size:14px}
.opts{display:flex;flex-wrap:wrap;gap:14px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.opts label{font-size:14px;display:flex;align-items:center;gap:6px}
button{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:11px 20px;font-size:15px;font-weight:600;cursor:pointer;margin-top:16px}
button:hover{filter:brightness(1.08)}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
pre{background:#0d0f12;color:#d6d6d0;border-radius:10px;padding:14px;overflow:auto;max-height:60vh;font-size:12.5px;line-height:1.45}
.mut{color:var(--mut)} code{font-family:ui-monospace,Menlo,monospace;font-size:12.5px;background:rgba(128,128,128,.13);padding:1px 5px;border-radius:4px}
table{width:100%;border-collapse:collapse;font-size:13.5px;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
td,th{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line)} tr:last-child td{border-bottom:none}
.badge{display:inline-block;font-size:12px;padding:3px 9px;border-radius:99px;border:1px solid var(--line);color:var(--mut)}
.badge.run{color:var(--accent);border-color:var(--accent)} .badge.done{color:var(--good);border-color:var(--good)}
.badge.fail{color:var(--bad);border-color:var(--bad)}
"""

def page(title, body):
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head>"
            f"<body><div class='wrap'>{body}</div></body></html>")

def list_reports():
    """Every case report, newest first: (label, relative path, mtime)."""
    out = []
    for h in CASES.glob("*/*.html"):
        out.append((h.parent.name, f"cases/{h.parent.name}/{h.name}", h.stat().st_mtime))
    return sorted(out, key=lambda x: x[2], reverse=True)

@app.get("/")
def index():
    f = ["<h1>KARGU-OSINT</h1><div class='sub'>Fill in what you know — leave the rest empty. "
         "Runs locally, only against targets you are authorised to investigate.</div>",
         "<form method='post' action='/run'>",
         f"<input type='hidden' name='csrf' value='{html.escape(CSRF_TOKEN)}'>"]
    for fl in FIELDS:
        f.append(f"<div class='field'><label for='{fl['key']}'>{html.escape(fl['title'])}"
                 + ("<span class='mut'> (comma separated)</span>" if fl["multi"] else "")
                 + f"</label><div class='hint'>{html.escape(fl['hint'])} &nbsp;·&nbsp; e.g. {html.escape(fl['example'])}</div>"
                 f"<input type='text' id='{fl['key']}' name='{fl['key']}' placeholder='leave empty to skip'></div>")
    f.append("<div class='field'><label for='case'>Case name</label>"
             "<div class='hint'>Names the folder and both files. Leave empty to generate one.</div>"
             "<input type='text' id='case' name='case' placeholder='auto'></div>")
    f.append("<h2>Scan options</h2><div class='opts'>"
             "<label><input type='checkbox' name='derive' checked> derive usernames</label>"
             "<label><input type='checkbox' name='api' checked> API sources</label>"
             "<label><input type='checkbox' name='tor'> route via Tor</label>"
             "<label><input type='checkbox' name='deep'> SpiderFoot deep scan</label>"
             + ("<label><input type='checkbox' name='faces'> local face matching (biometric — lawful basis required)</label>"
                "<label><input type='checkbox' name='deepface'> DeepFace re-check (stamps what it cannot confirm)</label>"
                "<label><input type='checkbox' name='clip'> CLIP similarity for reference photos</label>"
                if ML_PY.exists() else "")
             + "</div><button type='submit'>Start scan</button></form>")

    reps = list_reports()
    f.append("<h2>Previous cases</h2>")
    if reps:
        f.append("<table><tr><th>Case</th><th>Created</th></tr>")
        for label, rel, mt in reps[:30]:
            when = datetime.datetime.fromtimestamp(mt).strftime("%Y-%m-%d %H:%M")
            f.append(f"<tr><td><a href='/report/{html.escape(rel)}'>{html.escape(label)}</a></td>"
                     f"<td class='mut'>{when}</td></tr>")
        f.append("</table>")
    else:
        f.append("<p class='mut'>No cases yet.</p>")
    return page("KARGU-OSINT", "".join(f))

def _rejected_html(rejected):
    if not rejected:
        return ""
    rows = "".join(f"<tr><td>{html.escape(t)}</td><td><code>{html.escape(v)}</code></td>"
                   f"<td class='mut'>{html.escape(why)}</td></tr>" for t, v, why in rejected)
    return ("<table><tr><th>Field</th><th>Value</th><th>Why it was rejected</th></tr>"
            + rows + "</table>")

@app.post("/run")
def start_run():
    if not _same_origin_ok(request):
        return page("KARGU-OSINT", "<h1>Rejected</h1><p class='mut'>This scan request did not come from "
                               "the local form (missing or stale token, or a cross-site submission). "
                               "Nothing was scanned.</p><p><a href='/'>← open the form</a></p>"), 403
    profile, rejected = {}, []
    for fl in FIELDS:
        raw = (request.form.get(fl["key"]) or "").strip()
        vals = []
        if raw:
            parts = [p.strip() for p in raw.split(",")] if fl["multi"] else [raw]
            for p in [x for x in parts if x]:
                okv, val = fl["validator"](p)
                if okv:
                    vals.append(val)
                else:
                    # Invalid values must be reported back, never silently dropped.
                    rejected.append((fl["title"], p, val))
        profile[fl["key"]] = list(dict.fromkeys(vals))
    if not any(profile[k["key"]] for k in FIELDS if k["key"] != "notes"):
        return page("KARGU-OSINT", "<h1>Nothing to scan</h1><p class='mut'>Every field was empty or invalid.</p>"
                               + _rejected_html(rejected) +
                               "<p><a href='/'>← back</a></p>"), 400
    if rejected:
        return page("KARGU-OSINT", "<h1>Check these values</h1>"
                    "<p class='mut'>Nothing has been scanned yet. Fix or remove them and submit again.</p>"
                    + _rejected_html(rejected) + "<p><a href='/'>← back to the form</a></p>"), 400

    case = slugify(request.form.get("case") or
                   (profile["name"][0] if profile["name"] else
                    (profile["username"][0] if profile["username"] else "target")))
    folder = CASES / f"{case}_{datetime.datetime.now():%Y%m%d-%H%M%S}"
    folder.mkdir(parents=True, exist_ok=True)
    tfile = folder / f"{case}.txt"
    tfile.write_text(build_profile_text(profile, case), encoding="utf-8")

    cmd = [sys.executable, str(OSINT / "osint_run.py"), str(tfile)]
    if not request.form.get("derive"): cmd.append("--no-derive")
    if not request.form.get("api"):    cmd.append("--no-api")
    if request.form.get("tor"):        cmd.append("--tor")
    if request.form.get("deep"):       cmd.append("--deep")
    if request.form.get("faces") and ML_PY.exists():    cmd.append("--faces")
    if request.form.get("deepface") and ML_PY.exists(): cmd.append("--deepface")
    if request.form.get("clip") and ML_PY.exists():     cmd.append("--clip")

    jid = uuid.uuid4().hex[:10]
    JOBS[jid] = {"log": [f"$ {' '.join(cmd)}"], "status": "running", "case": folder.name, "report": None}
    threading.Thread(target=_worker, args=(jid, cmd, tfile, folder), daemon=True).start()
    return redirect(url_for("job_page", jid=jid))

def _worker(jid, cmd, tfile, folder):
    env = dict(os.environ)
    env["PATH"] = f"{OSINT/'bin'}:{env.get('PATH','')}"
    job = JOBS[jid]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, errors="replace", env=env, bufsize=1)
        for line in p.stdout:
            job["log"].append(re.sub(r"\x1b\[[0-9;]*m", "", line.rstrip()))
        p.wait()
        job["status"] = "done" if p.returncode == 0 else f"exit {p.returncode}"
    except Exception as e:
        job["log"].append(f"ERROR: {e}")
        job["status"] = "error"
    rep = folder / f"{tfile.stem}.html"
    if rep.exists():
        job["report"] = f"cases/{folder.name}/{rep.name}"

@app.get("/job/<jid>")
def job_page(jid):
    if jid not in JOBS:
        abort(404)
    j = JOBS[jid]
    body = (f"<h1>Scanning · {html.escape(j['case'])}</h1>"
            f"<div class='sub'>Status: <span id='st' class='badge run'>{html.escape(j['status'])}</span> "
            f"&nbsp;·&nbsp; <a href='/'>new scan</a></div>"
            f"<div id='link'></div><pre id='log'>loading…</pre>"
            "<script>"
            "async function tick(){const r=await fetch('/api/job/" + jid + "');const j=await r.json();"
            "const l=document.getElementById('log');const atEnd=l.scrollTop+l.clientHeight>=l.scrollHeight-40;"
            "l.textContent=j.log.join('\\n');if(atEnd)l.scrollTop=l.scrollHeight;"
            # Only 'done' renders green; every other non-running status must show as a failure.
            "const s=document.getElementById('st');s.textContent=j.status;"
            "s.className='badge '+(j.status=='running'?'run':(j.status=='done'?'done':'fail'));"
            "if(j.report){document.getElementById('link').innerHTML="
            "\"<p><a href='/report/\"+j.report+\"'>📄 Open the readable report →</a></p>\";}"
            "if(j.status=='running')setTimeout(tick,1500);}tick();"
            "</script>")
    return page(f"KARGU-OSINT · {j['case']}", body)

@app.get("/api/job/<jid>")
def job_api(jid):
    if jid not in JOBS:
        abort(404)
    j = JOBS[jid]
    return jsonify(log=j["log"][-400:], status=j["status"], report=j["report"])

@app.get("/report/<path:rel>")
def report(rel):
    target = (OSINT / rel).resolve()
    # is_relative_to, not startswith: a prefix match would also admit cases-backup/ or cases.old.
    if not target.is_relative_to(CASES.resolve()):
        abort(403)
    if not target.is_file():
        abort(404)
    return send_file(target)

def free_port(start):
    for p in range(start, start + 12):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
    return start

def open_browser(url):
    time.sleep(1.4)
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return
    try:
        subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="KARGU-OSINT local web UI")
    ap.add_argument("--port", type=int, default=int(os.environ.get("OSINT_UI_PORT", "8787")))
    ap.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    a = ap.parse_args()
    port = free_port(a.port)
    url = f"http://127.0.0.1:{port}/?t={ACCESS_TOKEN}"
    print(f"\n  KARGU-OSINT UI  ->  {url}")
    print("  Keep this terminal open; the site is served by this process.")
    print("  The link carries this process's access token — without it the UI answers 403.")
    print("  Press Ctrl+C to stop.\n", flush=True)
    if not a.no_browser:
        threading.Thread(target=open_browser, args=(url,), daemon=True).start()
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
