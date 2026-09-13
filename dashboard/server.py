#!/usr/bin/env python3
"""KARGU-OSINT fusion dashboard: scan intake plus a three-panel view over every case.

Left: identity (the scanner's own output). Middle: map + GDELT / Telegram / Sentinel feeds.
Right: captured pictures, same-photo groups and the opt-in local face / CLIP analysis.

Runs on the system interpreter; the vision stack (ml/.venv) and Telethon are only invoked as
subprocesses, so the dashboard starts without them. Loopback only, per-process access token
in the printed link; scan launches additionally need the CSRF token.
"""
import argparse, datetime, io, json, os, pathlib, re, secrets, socket, subprocess, sys, threading, time, uuid
from urllib.parse import urlparse

from flask import Flask, Response, abort, jsonify, redirect, render_template, request, send_file

OSINT = pathlib.Path(os.environ.get("OSINT_HOME") or pathlib.Path(__file__).resolve().parent.parent)
sys.path.insert(0, str(OSINT))
from osint_wizard import FIELDS, ML_PY, slugify, build_profile_text  # noqa: E402
from feeds import gdelt, sentinel  # noqa: E402

CASES = OSINT / "cases"
CASES.mkdir(parents=True, exist_ok=True)
DASH = pathlib.Path(__file__).resolve().parent
VISION = OSINT / "ml" / "vision.py"
TG_SEARCH = OSINT / "feeds" / "telegram_search.py"
SIDECAR = ".vision.json"
MAX_PHOTOS, MAX_PHOTO_BYTES = 8, 15_000_000
IMAGE_EXT = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp", "GIF": ".gif", "BMP": ".bmp"}

app = Flask(__name__, template_folder=str(DASH / "templates"), static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_PHOTOS * MAX_PHOTO_BYTES + 1_000_000
ACCESS_TOKEN = secrets.token_urlsafe(24)
COOKIE = "kargu_dash"
CSRF_TOKEN = secrets.token_urlsafe(32)
LOCAL = {"127.0.0.1", "localhost", "::1", "[::1]"}
JOBS = {}


def _token_ok(value):
    # compare_digest raises on non-ASCII str input; compare bytes so a junk token gets a 403, not a 500
    return secrets.compare_digest((value or "").encode("utf-8", "surrogateescape"), ACCESS_TOKEN.encode())


@app.before_request
def _gate():
    if _token_ok(request.cookies.get(COOKIE)):
        return None
    t = request.args.get("t") or ""
    if t and _token_ok(t):
        resp = redirect(request.path or "/")
        resp.set_cookie(COOKIE, ACCESS_TOKEN, httponly=True, samesite="Strict")
        return resp
    abort(403, "Private to the terminal that started it — open the printed link.")


def _same_origin_ok(req):
    """Reject cross-site submissions and DNS-rebinding hosts before anything is launched."""
    tok = req.form.get("csrf") or req.headers.get("X-CSRF") or ""
    if not secrets.compare_digest(tok.encode("utf-8", "surrogateescape"), CSRF_TOKEN.encode()):
        return False
    if (req.host or "").rsplit(":", 1)[0] not in LOCAL:
        return False
    for hdr in ("Origin", "Referer"):
        v = req.headers.get(hdr)
        if v and (urlparse(v).hostname or "") not in LOCAL:
            return False
    return True


# ---------------- cases ----------------
def _export(folder):
    """The scanner's JSON export in a case folder (sidecars excluded), or None."""
    want = folder / (folder.name.rsplit("_", 1)[0] + ".json")
    if want.is_file():
        return want
    for p in sorted(folder.glob("*.json")):
        if not p.name.endswith(SIDECAR):
            return p
    return None


def _cases():
    """(folder, stem, mtime) for every case folder with an export, newest first."""
    out = []
    for d in CASES.iterdir():
        if d.is_dir() and not d.is_symlink():
            j = _export(d)
            if j:
                out.append((d.name, j.stem, j.stat().st_mtime))
    return sorted(out, key=lambda x: -x[2])


def _find_case(name):
    """Folder name or case stem -> export path; the newest folder wins when stems collide."""
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        return None
    d = CASES / name
    if d.is_dir() and not d.is_symlink():
        return _export(d)
    for folder, stem, _ in _cases():
        if stem == name:
            return _export(CASES / folder)
    return None


_CACHE = {}


def _read(j):
    key, mt = str(j), j.stat().st_mtime
    hit = _CACHE.get(key)
    if hit and hit[0] == mt:
        return hit[1]
    doc = json.loads(j.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("export is not an object")
    _CACHE[key] = (mt, doc)
    return doc


def load_case(j):
    """Export plus the dashboard's own vision sidecar when one exists."""
    doc = dict(_read(j))
    doc["folder"], doc["case"] = j.parent.name, j.stem
    side = j.parent / (j.stem + SIDECAR)
    if side.is_file():
        try:
            doc["vision"] = json.loads(side.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    doc["ml_available"] = ML_PY.exists()
    tg = j.parent / "telegram.jsonl"
    doc["telegram_listener"] = tg.is_file()
    return doc


def _inline_json(doc):
    """JSON safe inside a <script> block: no '<' survives, so '</script>' cannot break out."""
    return json.dumps(doc, ensure_ascii=False).replace("<", "\\u003c")


def _pretty_ts(ts):
    s = str(ts or "")
    if len(s) == 15 and s[8] == "-":
        return f"{s[:4]}-{s[4:6]}-{s[6:8]} {s[9:11]}:{s[11:13]}"
    return s


def _route(doc):
    op = doc.get("opsec") or {}
    eg = op.get("egress") or {}
    if op.get("egress_changed"):
        return "exit changed", "bad"
    if eg.get("tor"):
        return "Tor", "ok"
    if eg.get("mullvad"):
        return "Mullvad", "ok"
    if eg.get("ip"):
        return "direct", "bad"
    return "exit unknown", ""


def _case_rows():
    rows = []
    for folder, stem, mt in _cases():
        row = {"folder": folder, "stem": stem, "when": time.strftime("%Y-%m-%d %H:%M", time.localtime(mt)),
               "verified": None, "route": "", "route_cls": "", "faces": False}
        try:
            doc = _read(CASES / folder / f"{stem}.json")
            st = doc.get("stats") or {}
            row["verified"], row["accounts"] = st.get("verified", 0), st.get("accounts", 0)
            row["route"], row["route_cls"] = _route(doc)
            row["faces"] = ((doc.get("vision") or {}).get("status") == "ran"
                            or (CASES / folder / f"{stem}{SIDECAR}").is_file())
        except (OSError, ValueError):
            row["error"] = "export unreadable"
        rows.append(row)
    return rows


@app.get("/static/<path:p>")
def static_files(p):
    root = (DASH / "static").resolve()
    if p in ("dash.js", "dash.css"):
        f = DASH / p
    else:
        f = (root / p).resolve()
        if not f.is_relative_to(root):
            abort(404)
    if not f.is_file():
        abort(404)
    return send_file(f)


@app.get("/")
def index():
    return render_template("cases.html", cases=_case_rows(), ml=ML_PY.exists())


@app.get("/cases")
def cases_alias():
    return redirect("/")


@app.get("/new")
def new_scan():
    return render_template("intake.html", csrf=CSRF_TOKEN, cases=_case_rows()[:8], ml=ML_PY.exists(),
                           fields=[f for f in FIELDS if f["key"] not in ("image",)])


@app.get("/case/<name>")
def case_view(name):
    j = _find_case(name)
    if not j:
        abort(404)
    try:
        doc = load_case(j)
    except (OSError, ValueError) as e:
        abort(500, f"{j.name} could not be read: {type(e).__name__}")
    return render_template("case.html", case=j.stem, folder=j.parent.name,
                           generated=_pretty_ts(doc.get("generated")), data=_inline_json(doc),
                           report=(j.parent / (j.stem + ".html")).is_file())


@app.get("/case/<name>/report")
def case_report(name):
    j = _find_case(name)
    rep = j.parent / (j.stem + ".html") if j else None
    if not (rep and rep.is_file()):
        abort(404)
    return send_file(rep)


@app.get("/api/case/<name>")
def api_case(name):
    j = _find_case(name)
    if not j:
        abort(404)
    return jsonify(load_case(j))


# ---------------- scan intake ----------------
def _validate_photos(files):
    """(blobs, error): every upload must decode as an image and stay under the size cap."""
    from PIL import Image
    out = []
    if len(files) > MAX_PHOTOS:
        return [], f"at most {MAX_PHOTOS} reference photos"
    for f in files:
        blob = f.read(MAX_PHOTO_BYTES + 1)
        if len(blob) > MAX_PHOTO_BYTES:
            return [], f"{f.filename}: larger than {MAX_PHOTO_BYTES // 1_000_000} MB"
        try:
            im = Image.open(io.BytesIO(blob))
            im.verify()
            ext = IMAGE_EXT.get(im.format or "")
        except Exception:
            ext = None
        if not ext:
            return [], f"{f.filename}: not a JPEG/PNG/WebP/GIF/BMP image"
        out.append((ext, blob))
    return out, None


@app.post("/api/run")
def api_run():
    if not _same_origin_ok(request):
        return jsonify(ok=False, error="rejected: missing CSRF token or cross-site request"), 403
    profile, rejected = {}, []
    for fl in FIELDS:
        raw = (request.form.get(fl["key"]) or "").strip()
        vals = []
        if raw:
            parts = [p.strip() for p in raw.split(",")] if fl["multi"] else [raw]
            for part in [x for x in parts if x]:
                okv, val = fl["validator"](part)
                if okv:
                    vals.append(val)
                else:
                    rejected.append(f"{fl['title']}: {part} — {val}")
        profile[fl["key"]] = list(dict.fromkeys(vals))
    photos, err = _validate_photos([f for f in request.files.getlist("photos") if f and f.filename])
    if err:
        rejected.append(err)
    if rejected:
        return jsonify(ok=False, error="check these values: " + "; ".join(rejected)), 400
    if not photos and not any(profile[k] for k in profile if k != "notes"):
        return jsonify(ok=False, error="nothing to scan: every field is empty"), 400

    case = slugify(request.form.get("case") or (profile["name"][0] if profile["name"] else
                   (profile["username"][0] if profile["username"] else "target")))
    folder = CASES / f"{case}_{datetime.datetime.now():%Y%m%d-%H%M%S}"
    folder.mkdir(parents=True, exist_ok=True)
    if photos:
        refs = folder / "refs"
        refs.mkdir(exist_ok=True)
        for i, (ext, blob) in enumerate(photos, 1):
            p = refs / f"ref{i:02d}{ext}"
            p.write_bytes(blob)
            profile["image"].append(str(p))
    tfile = folder / f"{case}.txt"
    tfile.write_text(build_profile_text(profile, case), encoding="utf-8")

    cmd = [sys.executable, str(OSINT / "osint_run.py"), str(tfile)]
    if not request.form.get("derive"): cmd.append("--no-derive")
    if not request.form.get("api"):    cmd.append("--no-api")
    if request.form.get("tor"):        cmd.append("--tor")
    if request.form.get("deep"):       cmd.append("--deep")
    if request.form.get("faces") and ML_PY.exists(): cmd.append("--faces")
    if request.form.get("clip") and ML_PY.exists():  cmd.append("--clip")
    jid = uuid.uuid4().hex[:10]
    JOBS[jid] = {"log": [f"$ {' '.join(cmd)}"], "status": "running", "case": folder.name, "export": False}
    threading.Thread(target=_worker, args=(jid, cmd, folder), daemon=True).start()
    return jsonify(ok=True, job_id=jid, case=folder.name)


def _worker(jid, cmd, folder):
    env = dict(os.environ)
    env["PATH"] = f"{OSINT / 'bin'}:{env.get('PATH', '')}"
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
    job["export"] = _export(folder) is not None


@app.get("/api/job/<jid>")
def api_job(jid):
    j = JOBS.get(jid)
    if not j:
        abort(404)
    return jsonify(log=j["log"][-400:], status=j["status"], case=j["case"], export=j["export"])


# ---------------- feeds ----------------
_GDELT_LOCK, _GDELT_LAST = threading.Lock(), [0.0]


@app.get("/api/gdelt")
def api_gdelt():
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify(error="no query")
    # GDELT allows one query every 5 s; queue rather than bounce the second click.
    with _GDELT_LOCK:
        wait = 5.2 - (time.time() - _GDELT_LAST[0])
        if wait > 0:
            time.sleep(wait)
        res = gdelt.search(f'"{q}"' if " " in q and not q.startswith('"') else q, maxrecords=25)
        _GDELT_LAST[0] = time.time()
    return jsonify(res)


def _telegram_configured():
    if os.environ.get("TELEGRAM_API_ID"):
        return True
    cfg = OSINT / "config" / ".env"
    return cfg.exists() and re.search(r"^\s*TELEGRAM_API_ID\s*=\s*\S", cfg.read_text(encoding="utf-8", errors="replace"), re.M) is not None


def _listener_hits(name, limit=25):
    j = _find_case(name) if name else None
    f = j.parent / "telegram.jsonl" if j else None
    if not (f and f.is_file()):
        return []
    rows = []
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines()[-2000:]:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("hit"):
            rows.append(r)
    return rows[-limit:][::-1]


@app.get("/api/telegram")
def api_telegram():
    q = (request.args.get("q") or "").strip()
    out = {"query": q, "messages": [], "listener": _listener_hits(request.args.get("case") or "")}
    if not _telegram_configured():
        out["error"] = ("Telegram is not configured: add TELEGRAM_API_ID / TELEGRAM_API_HASH to config/.env "
                        "and log in once with  ml/.venv/bin/python feeds/telegram_search.py --login")
        return jsonify(out)
    if not ML_PY.exists():
        out["error"] = "Telethon runs in ml/.venv — run dashboard/install-ml.sh first"
        return jsonify(out)
    if not q:
        return jsonify(out)
    try:
        # "--" keeps a query such as "--login" from being parsed as an option
        r = subprocess.run([str(ML_PY), str(TG_SEARCH), "--", q], stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=90)
        if r.returncode != 0 or not r.stdout.strip():
            res = {"error": "Telegram search failed: " + (r.stderr or "no output").strip()[-300:]}
        else:
            res = json.loads(r.stdout)
    except (subprocess.SubprocessError, ValueError) as e:
        res = {"error": f"Telegram search failed ({type(e).__name__})"}
    out.update(res)
    return jsonify(out)


@app.get("/api/sentinel")
def api_sentinel():
    try:
        lat, lon = float(request.args.get("lat")), float(request.args.get("lon"))
        days = max(1, min(365, int(request.args.get("days") or 30)))
    except (TypeError, ValueError):
        return jsonify(error="lat and lon are required")
    return jsonify(sentinel.quicklooks(lat, lon, days=days))


# ---------------- local vision ----------------
def _vision(name, args, timeout=1800):
    j = _find_case(name)
    if not j:
        return {"error": "case not found"}, None
    if not ML_PY.exists():
        return {"error": "local vision stack not installed: run dashboard/install-ml.sh"}, j
    try:
        out = subprocess.run([str(ML_PY), str(VISION)] + args, stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=timeout)
        res = json.loads(out.stdout) if out.stdout.strip() else {"error": (out.stderr or "no output").strip()[-400:]}
    except (subprocess.SubprocessError, ValueError) as e:
        res = {"error": f"vision stage failed ({type(e).__name__})"}
    return res, j


@app.post("/api/vision/<name>")
def api_vision(name):
    faces = request.args.get("faces") == "1"
    clip = request.args.get("clip") == "1"
    if not (faces or clip):
        return jsonify(error="nothing requested: faces=1 and/or clip=1")
    try:
        thr = float(request.args.get("threshold") or 0.5)
    except ValueError:
        thr = 0.5
    args = ["analyze", None, "--threshold", str(thr)] + (["--faces"] if faces else []) + (["--clip"] if clip else [])
    j = _find_case(name)
    if not j:
        return jsonify(error="case not found")
    args[1] = str(j)
    res, j = _vision(name, args)
    if not res.get("error"):
        res["status"], res["source"] = "ran", "dashboard"
        res["when"] = datetime.datetime.now().isoformat(timespec="seconds")
        try:
            (j.parent / (j.stem + SIDECAR)).write_text(json.dumps(res, ensure_ascii=False), encoding="utf-8")
        except OSError:
            res["note"] = "result could not be saved next to the case"
    return jsonify(res)


@app.post("/api/faces/<name>")
def api_faces(name):
    return redirect(f"/api/vision/{name}?faces=1", code=307)


@app.post("/api/clip/<name>")
def api_clip(name):
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify(error="empty query")
    j = _find_case(name)
    if not j:
        return jsonify(error="case not found")
    res, _ = _vision(name, ["clip", str(j), f"--query={q}"], timeout=600)   # "=" form: a query may start with "-"
    return jsonify(res)


# ---------------- launcher ----------------
def free_port(start):
    for p in range(start, start + 12):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", p)) != 0:
                return p
    return start


def open_browser(url):
    time.sleep(1.2)
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        try:
            subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="KARGU-OSINT fusion dashboard")
    ap.add_argument("--port", type=int, default=int(os.environ.get("KARGU_DASH_PORT", "8788")))
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    port = free_port(a.port)
    url = f"http://127.0.0.1:{port}/?t={ACCESS_TOKEN}"
    print(f"\n  KARGU-OSINT Dashboard  ->  {url}")
    print(f"  Cases: {CASES}")
    print("  Loopback only; the link carries this process's access token. Ctrl+C to stop.\n", flush=True)
    if not a.no_browser:
        threading.Thread(target=open_browser, args=(url,), daemon=True).start()
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
