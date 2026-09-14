#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KARGU-OSINT Orchestrator — takes a target profile .txt, runs the tool chain in a
logical order, enriches with API sources, then writes an updated target file,
a single readable HTML report next to it.

Usage:
    kargu <target.txt> [--deep] [--tor] [--depth 1] [--no-api]

Target file format (key: value, a key may repeat):
    name: John Doe
    username: johndoe
    email: john@example.com
    phone: +90 5xx xxx xx xx
    domain: example.com
    file: /path/photo.jpg      # for metadata
    notes: free text
"""
import argparse, base64, hashlib, html, io, json, math, os, posixpath, re, subprocess, sys, shutil, datetime, tempfile, threading, time, pathlib, urllib.parse
from concurrent.futures import ThreadPoolExecutor

HOME = pathlib.Path.home()
# Anchored on this file's directory so the tree can be moved; OSINT_HOME overrides for
# anyone keeping the data apart from the code.
OSINT = pathlib.Path(os.environ.get("OSINT_HOME") or pathlib.Path(__file__).resolve().parent)
BIN = OSINT / "bin"
CASES = OSINT / "cases"          # one folder per investigation: <case>.txt + .html + .json
RESOURCES = OSINT / "resources"  # vendored OSINT Framework dataset (MIT, see SOURCE.md)
CONFIG = OSINT / "config"
ML_PY = OSINT / "ml" / ".venv" / "bin" / "python"   # optional local vision stack (dashboard/install-ml.sh)
VISION_PY = OSINT / "ml" / "vision.py"
DEEPFACE_WEIGHTS = pathlib.Path(os.environ.get("DEEPFACE_HOME") or pathlib.Path.home()) / ".deepface" / "weights"
FACE_STRONG = 0.65                                   # InsightFace cosine read as a confident same-person call
DISPUTED_MARK = "DEEPFACE NOT CONFIRMED"
IMAGES_DIR = None                                    # <case folder>/images, set by main(); None in tests
for d in (CASES, CONFIG):
    d.mkdir(parents=True, exist_ok=True)

# ---------------- API keys (config/.env) ----------------
def load_env():
    """Read config/.env into a dict. Real environment variables win."""
    env = {}
    p = CONFIG / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            v = v.strip().strip('"').strip("'")
            if v:
                env[k.strip().upper()] = v
    for k in list(env) + ["NUMVERIFY_API_KEY", "VIRUSTOTAL_API_KEY", "CHAOS_API_KEY",
                          "HUNTER_API_KEY", "HIBP_API_KEY"]:
        if os.environ.get(k):
            env[k] = os.environ[k]
    # h8mail's ini keys must be known to _redact(): its stderr can quote the config and
    # is rendered into the report.
    ini = CONFIG / "h8mail_config.ini"
    if ini.exists():
        for line in ini.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\S.*?)\s*$", line)
            if m and not line.lstrip().startswith(("#", ";", "[")):
                env.setdefault("H8MAIL_" + m.group(1).upper(), m.group(2))
    return env

API = load_env()
def key(name):
    return API.get(name) or ""

# ---------------- HTTP helper ----------------
UA = "Mozilla/5.0 (X11; Linux x86_64) osint-orchestrator/2.0"
def _redact(text):
    """Strip key material out of anything bound for the report, console or UI log.

    hunter.io and numverify carry the key in the query string, and requests puts the
    full URL into its exception text, which is rendered as a skip reason."""
    s = str(text or "")
    s = re.sub(r"((?:access_key|api_key|apikey|key|token)=)[^&\s]+", r"\1<redacted>", s, flags=re.I)
    for v in API.values():
        if v and len(v) >= 8:
            s = s.replace(v, "<redacted>")
    return s

def http_json(url, headers=None, params=None, timeout=30):
    """GET -> (status, parsed_json_or_None, error_text). Never raises."""
    hdr = {"User-Agent": UA, "Accept": "application/json"}
    hdr.update(headers or {})
    try:
        import requests
        _opsec("third_parties", _host(url))
        r = requests.get(url, headers=hdr, params=params or {}, timeout=timeout, proxies=PROXIES)
        try:
            return r.status_code, r.json(), ""
        except Exception:
            return r.status_code, None, _redact((r.text or "")[:300])
    except Exception as e:
        return 0, None, _redact(f"{type(e).__name__}: {e}")

# ---------------- console ----------------
_TTY = sys.stdout.isatty()
def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _TTY else s
def head(s):   print("\n" + _c("1;36", s), flush=True)
def step(s):   print(_c("1;33", s), flush=True)
def log(s):    print(f"    {s}", flush=True)
def ok(s):     print(_c("32", f"    -> {s}"), flush=True)
def warn(s):   print(_c("33", f"    ! {s}"), flush=True)

# ---------------- tool resolution ----------------
def tool(name):
    p = BIN / name
    if p.exists():
        return str(p)
    return shutil.which(name)

PROXYCHAINS = shutil.which("proxychains4") or shutil.which("proxychains")

# --- Tor ---------------------------------------------------------------------
# Both paths (proxychains for tools, socks5h for requests) must work or --tor refuses to run.
TOR_SOCKS = os.environ.get("OSINT_TOR_SOCKS", "socks5h://127.0.0.1:9050")
USE_TOR = False          # set from --tor after the checks below pass
PROXIES = None

def tor_listening(host="127.0.0.1", port=9050, timeout=3):
    import socket as _s
    try:
        with _s.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def tor_confirmed():
    """Ask the Tor project whether we are really exiting through Tor."""
    try:
        import requests
        r = requests.get("https://check.torproject.org/api/ip",
                         proxies={"http": TOR_SOCKS, "https": TOR_SOCKS}, timeout=25)
        j = r.json()
        return bool(j.get("IsTor")), j.get("IP")
    except Exception as e:
        return False, f"{type(e).__name__}"

PCHAINS_CONF = OSINT / ".tor" / "proxychains.conf"

def write_proxychains_conf(port=9050):
    """Write our own proxychains.conf: the distro default is socks4, which cannot resolve
    hostnames through Tor and leaks DNS."""
    try:
        PCHAINS_CONF.parent.mkdir(parents=True, exist_ok=True)
        PCHAINS_CONF.write_text(
            "# generated by KARGU-OSINT — socks5 so DNS is resolved through Tor\n"
            "strict_chain\nproxy_dns\nremote_dns_subnet 224\n"
            "tcp_read_time_out 15000\ntcp_connect_time_out 8000\n"
            f"[ProxyList]\nsocks5 127.0.0.1 {port}\n", encoding="utf-8")
        return True
    except Exception:
        return False

def egress_info(via_tor=False):
    """Current egress IP as the internet sees it; reported verbatim in the OPSEC section."""
    try:
        import requests
        px = {"http": TOR_SOCKS, "https": TOR_SOCKS} if via_tor else None
        r = requests.get("https://am.i.mullvad.net/json", timeout=25, proxies=px,
                         headers={"User-Agent": UA})
        j = r.json()
        return {"ip": j.get("ip"), "country": j.get("country"), "city": j.get("city"),
                "org": j.get("organization"), "mullvad": bool(j.get("mullvad_exit_ip")),
                "tor": via_tor}
    except Exception as e:
        return {"error": f"{type(e).__name__}", "tor": via_tor}

def enable_tor():
    """Return (ok, message). Never enables Tor half-way."""
    global USE_TOR, PROXIES
    try:
        import socks  # noqa: F401  (PySocks: required by requests for socks5h)
    except ImportError:
        return False, ("PySocks is missing, so Python requests cannot use Tor.\n"
                       "     Install it with:  pip install --user 'requests[socks]'")
    if not tor_listening():
        return False, (f"nothing is listening on {TOR_SOCKS}.\n"
                       "     Start it with:  kargu-tor start     (no root needed)")
    ok, ip = tor_confirmed()
    if not ok:
        return False, f"the SOCKS port answers but check.torproject.org says this is not Tor ({ip})."
    USE_TOR = True
    PROXIES = {"http": TOR_SOCKS, "https": TOR_SOCKS}
    write_proxychains_conf()
    msg = f"routing through Tor · exit IP {ip}"
    if not PROXYCHAINS:
        msg += ("\n     WARNING: proxychains is not installed, so the external tools "
                "(sherlock, maigret, holehe, theHarvester ...) still go out over your normal "
                "connection. Only this program's own requests are anonymised. "
                "Install proxychains-ng for full coverage.")
    return True, msg

_RESTORE = []          # cleanup callbacks run on every exit path, including Ctrl+C

def _run_restore():
    while _RESTORE:
        try:
            _RESTORE.pop()()
        except Exception:
            pass

def _mullvad_lockdown_get():
    rc, out, _ = run([shutil.which("mullvad"), "lockdown-mode", "get"], timeout=15)
    tail = out.lower().rsplit(":", 1)[-1].strip()
    return "on" if tail.startswith("on") else "off" if tail.startswith("off") else None

def _mullvad_lockdown_set(state):
    rc, _, _ = run([shutil.which("mullvad"), "lockdown-mode", "set", state], timeout=15)
    return rc == 0

def run(cmd, timeout=180, use_tor=False):
    """Run a tool; return (rc, stdout, stderr). Never raises."""
    if (use_tor or USE_TOR) and PROXYCHAINS:
        pre = [PROXYCHAINS, "-f", str(PCHAINS_CONF)] if PCHAINS_CONF.exists() else [PROXYCHAINS]
        cmd = pre + ["-q"] + cmd
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace")
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"TIMEOUT ({timeout}s)"
    except FileNotFoundError:
        return 127, "", "tool not found"
    except Exception as e:
        return 1, "", f"error: {e}"

def run_bytes(cmd, timeout=30, use_tor=False):
    """Run a tool and return (rc, stdout_bytes, stderr_str). Never raises."""
    if (use_tor or USE_TOR) and PROXYCHAINS:
        pre = [PROXYCHAINS, "-f", str(PCHAINS_CONF)] if PCHAINS_CONF.exists() else [PROXYCHAINS]
        cmd = pre + ["-q"] + cmd
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        err = p.stderr.decode("utf-8", errors="replace") if p.stderr else ""
        return p.returncode, p.stdout or b"", err
    except subprocess.TimeoutExpired:
        return 124, b"", f"TIMEOUT ({timeout}s)"
    except FileNotFoundError:
        return 127, b"", "tool not found"
    except Exception as e:
        return 1, b"", f"error: {e}"

def _fail(rc, err, parsed):
    """Why a tool produced nothing, or "" when it ran cleanly.

    A non-zero rc only counts when nothing was parsed: several tools set odd exit codes
    on partial success, and a crash must not reach the report as a clean negative."""
    if rc == 0 or parsed:
        return ""
    if rc == 124:
        return "timed out — no result, this is not a clean negative"
    tail = ""
    for line in reversed((err or "").strip().splitlines()):
        if line.strip():
            tail = line.strip()[:140]
            break
    if rc == 127:
        # A wrapper may exit 127 for its own reason (bin/sf with the docker image missing).
        return _redact(tail) or "tool not found"
    return _redact(f"exited {rc}" + (f": {tail}" if tail else ""))

# ---------------- target parsing ----------------
LIST_KEYS = {"name", "username", "email", "phone", "domain", "file", "image", "notes"}
def parse_target(path):
    prof = {k: [] for k in LIST_KEYS}
    raw = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if ":" in s:
            k, v = s.split(":", 1)
            k = k.strip().lower(); v = v.strip()
            if k in ("file", "image") and v:
                # Only ~ is expanded: expandvars() would put "$HUNTER_API_KEY" into the report.
                if not (v.startswith("http://") or v.startswith("https://")):
                    v = os.path.expanduser(v)
            if k in prof and v:
                if v.startswith("-"):
                    # Identifiers reach external tools as positional arguments; "--help"
                    # or "-rf" would be parsed as a flag.
                    warn(f"ignoring {k} value {v!r}: identifiers cannot start with '-'")
                    continue
                if v not in prof[k]:
                    prof[k].append(v)
    return prof

def _slug(s):
    tr = str.maketrans("çğıöşüÇĞİÖŞÜ", "cgiosucgiosu")
    return re.sub(r"[^a-z0-9]", "", s.translate(tr).lower())

def derive_usernames(prof, cap=3):
    """Build candidate usernames from the name / e-mail local part."""
    known = set(u.lower() for u in prof["username"])
    cands = []
    def add(c):
        c = (c or "").strip()
        if c and c.lower() not in known and c.lower() not in {x.lower() for x in cands}:
            cands.append(c)
    for e in prof["email"]:            # e-mail local part = strongest candidate
        lp = e.split("@")[0]
        add(lp)
        if "." in lp: add(lp.replace(".", ""))
        if "_" in lp: add(lp.replace("_", ""))
    for n in prof["name"]:
        parts = [_slug(p) for p in re.split(r"\s+", n) if _slug(p)]
        if len(parts) >= 2:
            add("".join(parts))              # aysenurgunes
            add(parts[0] + parts[-1])        # aysegunes
            add(parts[0] + "." + parts[-1])  # ayse.gunes
            add(parts[-1] + parts[0])        # gunesayse
    return cands[:cap]

# ---------------- STAGE 1: IDENTITY (username) ----------------
def stage_sherlock(username):
    exe = tool("sherlock")
    if not exe:
        return {"tool": "sherlock", "skipped": "not installed", "hits": []}
    # --no-txt: sherlock otherwise drops a <username>.txt into the working directory
    rc, out, err = run([exe, username, "--no-color", "--print-found", "--no-txt",
                        "--timeout", "15"], timeout=240)
    hits = []
    for m in re.finditer(r"^\[\+\]\s*(.+?):\s*(https?://\S+)", out, re.M):
        hits.append({"site": m.group(1).strip(), "url": m.group(2).strip()})
    return {"tool": "sherlock", "hits": hits, "failed": _fail(rc, err, hits)}

def stage_maigret(username):
    exe = tool("maigret")
    if not exe:
        return {"tool": "maigret", "skipped": "not installed", "hits": []}
    with tempfile.TemporaryDirectory() as td:
        # --no-recursion/--no-extracting: do not branch into other usernames/IDs
        # (without these maigret returns hundreds of unrelated false positives)
        rc, out, err = run([exe, username, "-J", "simple", "-fo", td, "--timeout", "15",
                            "--no-progressbar", "--no-recursion", "--no-extracting",
                            "--id-type", "username"], timeout=300)
        hits = []
        for jf in pathlib.Path(td).glob("*.json"):
            try:
                data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
                for site, info in (data.items() if isinstance(data, dict) else []):
                    st = (info or {}).get("status", {})
                    if isinstance(st, dict) and st.get("status") == "Claimed":
                        hits.append({"site": site, "url": (info.get("url_user") or "")})
            except Exception:
                pass
        if not hits:  # stdout fallback
            for m in re.finditer(r"\[\+\]\s*(.+?):\s*(https?://\S+)", out):
                hits.append({"site": m.group(1).strip(), "url": m.group(2).strip()})
    # safety filter: drop results whose URL does not contain the queried username
    us = _slug(username)
    if us:
        hits = [h for h in hits if not h.get("url") or us in _slug(h.get("url", ""))]
    return {"tool": "maigret", "hits": hits, "failed": _fail(rc, err, hits)}

# ---------------- STAGE 2: E-MAIL ----------------
def stage_holehe(email):
    exe = tool("holehe")
    if not exe:
        return {"tool": "holehe", "skipped": "not installed", "used": []}
    rc, out, err = run([exe, email, "--only-used", "--no-color"], timeout=180)
    # Require a dot: holehe's own colour legend ("[+] Email used") matches a bare \S+.
    used = re.findall(r"^\[\+\]\s*(\S+\.\S+)", out, re.M)
    return {"tool": "holehe", "used": used, "failed": _fail(rc, err, used)}

def h8mail_sources():
    """Breach sources h8mail can actually query, read from config/h8mail_config.ini.

    Returns (config_path_or_None, [source names]). The config is passed only when it has
    at least one live key; with none, "0 breaches" is not a measurement."""
    cfg = CONFIG / "h8mail_config.ini"
    if not cfg.exists():
        return None, []
    names = []
    for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith((";", "#", "[")) or "=" not in s:
            continue
        k, _, v = s.partition("=")
        if v.strip():
            names.append(k.strip())
    return cfg, names

def stage_h8mail(email):
    exe = tool("h8mail")
    if not exe:
        return {"tool": "h8mail", "skipped": "not installed", "breaches": []}
    cfg, sources = h8mail_sources()
    with tempfile.TemporaryDirectory() as td:
        outj = os.path.join(td, "h.json")
        cmd = [exe, "-t", email, "--json", outj]
        if cfg and sources:
            cmd += ["-c", str(cfg)]
        rc, out, err = run(cmd, timeout=180)
        breaches = []
        try:
            if os.path.exists(outj):
                data = json.loads(pathlib.Path(outj).read_text(errors="replace"))
                for t in (data.get("targets", []) if isinstance(data, dict) else []):
                    for d in t.get("data", []):
                        breaches.append(str(d)[:200])
        except Exception:
            pass
        note = _redact(err.strip())[:120] if not breaches else ""
        if not sources:
            note = ("no breach source is configured, so this is not a measured result — "
                    "add a key in config/h8mail_config.ini (e.g. hibp) and uncomment it")
        return {"tool": "h8mail", "breaches": breaches, "sources": sources,
                "failed": _fail(rc, err, breaches), "note": note}

def stage_hibp(email):
    """Have I Been Pwned v3 — needs a paid key; skipped silently without one."""
    k = key("HIBP_API_KEY")
    if not k:
        return {"tool": "hibp", "skipped": "no API key", "breaches": []}
    st, js, err = http_json(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                            headers={"hibp-api-key": k}, params={"truncateResponse": "false"})
    if st == 404:
        return {"tool": "hibp", "breaches": [], "note": "no breach found"}
    if st != 200 or not isinstance(js, list):
        return {"tool": "hibp", "skipped": f"HTTP {st} {err}"[:120], "breaches": []}
    out = [{"name": b.get("Name"), "domain": b.get("Domain"), "date": b.get("BreachDate"),
            "count": b.get("PwnCount"), "data": b.get("DataClasses", [])} for b in js]
    return {"tool": "hibp", "breaches": out}

def stage_gravatar(email):
    """Gravatar profile lookup (free, no key) — often leaks a real name + linked accounts."""
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    st, js, err = http_json(f"https://www.gravatar.com/{h}.json")
    if st == 404:
        return {"tool": "gravatar", "found": False}
    if st != 200 or not isinstance(js, dict):
        return {"tool": "gravatar", "found": False, "note": f"HTTP {st}"}
    try:
        e = (js.get("entry") or [{}])[0]
    except Exception:
        e = {}
    if not e:
        return {"tool": "gravatar", "found": False}
    return {"tool": "gravatar", "found": True, "hash": h,
            "profile_url": e.get("profileUrl"),
            "display_name": e.get("displayName"),
            "name": e.get("name"),
            "location": e.get("currentLocation"),
            "about": (e.get("aboutMe") or "")[:400],
            "accounts": [{"site": a.get("shortname") or a.get("domain"), "url": a.get("url"),
                          "username": a.get("username")} for a in (e.get("accounts") or [])],
            "urls": [u.get("value") for u in (e.get("urls") or [])],
            "photos": [p.get("value") for p in (e.get("photos") or [])]}

def stage_socialscan(queries):
    exe = tool("socialscan")
    if not exe or not queries:
        return {"tool": "socialscan", "skipped": "not installed / no query", "results": []}
    with tempfile.TemporaryDirectory() as td:
        outj = os.path.join(td, "ss.json")
        rc, out, err = run([exe] + queries + ["--json", outj], timeout=180)
        results = []
        try:
            if os.path.exists(outj):
                data = json.loads(pathlib.Path(outj).read_text(errors="replace"))
                # socialscan writes {query: [ {platform, available, valid, …}, … ]}.
                if isinstance(data, dict):
                    for q, rows in data.items():
                        for r in (rows if isinstance(rows, list) else []):
                            results.append({"query": r.get("query", q),
                                            "platform": r.get("platform"),
                                            "taken": str(r.get("available")).lower() == "false",
                                            "valid": str(r.get("valid")).lower() == "true",
                                            "success": str(r.get("success")).lower() == "true",
                                            "message": r.get("message") or ""})
                elif isinstance(data, list):
                    results = data
        except Exception:
            pass
    return {"tool": "socialscan", "results": results,
            "failed": _fail(rc, err, results)}

# ---------------- STAGE 4: DOMAIN / INFRASTRUCTURE ----------------
def stage_theharvester(domain, use_api=True):
    exe = tool("theHarvester") or tool("theharvester")
    if not exe:
        return {"tool": "theHarvester", "skipped": "not installed", "emails": [], "hosts": []}
    # theHarvester rejects the whole run on any unknown source name, so this list must
    # track the installed major (5.0.0 dropped bing and threatminer).
    sources = ["duckduckgo", "crtsh", "hackertarget", "rapiddns", "otx", "urlscan"]
    if use_api and key("VIRUSTOTAL_API_KEY"):
        sources.append("virustotal")
    if use_api and key("CHAOS_API_KEY"):
        sources.append("projectdiscovery")
    if use_api and key("HUNTER_API_KEY"):
        sources.append("hunter")
    with tempfile.TemporaryDirectory() as td:
        base = os.path.join(td, "th")
        rc, out, err = run([exe, "-d", domain, "-b", ",".join(sources), "-f", base], timeout=420)
        emails, hosts = [], []
        for jf in pathlib.Path(td).glob("*.json"):
            try:
                data = json.loads(jf.read_text(errors="replace"))
                emails += data.get("emails", []) or []
                hosts += [h if isinstance(h, str) else str(h) for h in (data.get("hosts", []) or [])]
            except Exception:
                pass
        fail = _fail(rc, err or out, emails or hosts)
        if not fail and "Invalid source" in (out + err):
            fail = "invalid source list — theHarvester refused to run"
        return {"tool": "theHarvester", "sources": sources, "failed": fail,
                "emails": sorted(set(emails)), "hosts": sorted(set(hosts))[:200]}

def stage_dnstwist(domain):
    exe = tool("dnstwist")
    if not exe:
        return {"tool": "dnstwist", "skipped": "not installed", "registered": []}
    rc, out, err = run([exe, "--format", "json", "--registered", domain], timeout=300)
    reg = []
    try:
        data = json.loads(out)
        for e in data:
            reg.append({"domain": e.get("domain"), "dns_a": e.get("dns_a"), "fuzzer": e.get("fuzzer")})
    except Exception:
        pass
    return {"tool": "dnstwist", "registered": reg}

def stage_crtsh(domain):
    """Certificate-transparency subdomains — free, no key.
    crt.sh is frequently overloaded (502/timeout), so retry and fall back to certspotter."""
    js, st, err = None, 0, ""
    for attempt in range(3):
        st, js, err = http_json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=45)
        if st == 200 and isinstance(js, list):
            break
        time.sleep(3)
    if st != 200 or not isinstance(js, list):
        return _certspotter(domain, why=f"crt.sh HTTP {st}")
    host_re = re.compile(r"^[a-z0-9][a-z0-9._\-]*\.[a-z]{2,}$")
    subs = set()
    for row in js:
        for field in ("name_value", "common_name"):
            for nv in str(row.get(field, "")).splitlines():
                nv = nv.strip().lstrip("*.").lower().rstrip(".")
                if nv.endswith("." + domain) or nv == domain:
                    if host_re.match(nv):
                        subs.add(nv)
    return {"tool": "crt.sh", "subdomains": sorted(subs)}

def _certspotter(domain, why=""):
    """Fallback certificate-transparency source when crt.sh is down (free, rate-limited)."""
    st, js, err = http_json("https://api.certspotter.com/v1/issuances",
                            params={"domain": domain, "include_subdomains": "true",
                                    "expand": "dns_names"}, timeout=45)
    if st != 200 or not isinstance(js, list):
        return {"tool": "crt.sh", "skipped": f"{why} · certspotter HTTP {st}"[:180], "subdomains": []}
    host_re = re.compile(r"^[a-z0-9][a-z0-9._\-]*\.[a-z]{2,}$")
    subs = set()
    for row in js:
        for nv in (row.get("dns_names") or []):
            nv = str(nv).strip().lstrip("*.").lower().rstrip(".")
            if (nv.endswith("." + domain) or nv == domain) and host_re.match(nv):
                subs.add(nv)
    return {"tool": "certspotter", "subdomains": sorted(subs),
            "note": f"crt.sh unavailable ({why}), used certspotter instead" if why else ""}

def stage_virustotal(domain):
    k = key("VIRUSTOTAL_API_KEY")
    if not k:
        return {"tool": "virustotal", "skipped": "no API key"}
    h = {"x-apikey": k}
    st, js, err = http_json(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=h)
    if st != 200 or not isinstance(js, dict):
        return {"tool": "virustotal", "skipped": f"HTTP {st} {err}"[:160]}
    a = (js.get("data") or {}).get("attributes") or {}
    recs = {}
    for r in (a.get("last_dns_records") or []):
        recs.setdefault(r.get("type"), []).append(str(r.get("value"))[:120])
    res = {"tool": "virustotal", "reputation": a.get("reputation"),
           "registrar": a.get("registrar"),
           "created": a.get("creation_date"),
           "categories": a.get("categories") or {},
           "analysis": a.get("last_analysis_stats") or {},
           "dns": recs,
           "whois": (a.get("whois") or "")[:1500]}
    st2, js2, _ = http_json(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
                            headers=h, params={"limit": 40})
    if st2 == 200 and isinstance(js2, dict):
        res["subdomains"] = [d.get("id") for d in (js2.get("data") or []) if d.get("id")]
    st3, js3, _ = http_json(f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions",
                            headers=h, params={"limit": 20})
    if st3 == 200 and isinstance(js3, dict):
        res["resolutions"] = [{"ip": (d.get("attributes") or {}).get("ip_address"),
                               "date": (d.get("attributes") or {}).get("date")}
                              for d in (js3.get("data") or [])]
    return res

def stage_chaos(domain):
    """ProjectDiscovery Chaos subdomain dataset (covers public bug-bounty scopes)."""
    k = key("CHAOS_API_KEY")
    if not k:
        return {"tool": "chaos", "skipped": "no API key", "subdomains": []}
    st, js, err = http_json(f"https://dns.projectdiscovery.io/dns/{domain}/subdomains",
                            headers={"Authorization": k})
    if st in (401, 403):
        return {"tool": "chaos", "subdomains": [],
                "skipped": "HTTP %d — this ProjectDiscovery key is not authorised for the Chaos "
                           "dataset (dns.projectdiscovery.io). Request Chaos access at "
                           "chaos.projectdiscovery.io with the same account." % st}
    if st != 200 or not isinstance(js, dict):
        return {"tool": "chaos", "skipped": f"HTTP {st} {err}"[:160], "subdomains": []}
    subs = [f"{s}.{domain}" if s else domain for s in (js.get("subdomains") or [])]
    return {"tool": "chaos", "subdomains": sorted(set(subs)),
            "note": "empty is normal: Chaos only indexes public bug-bounty scopes"}

def stage_hunter_domain(domain):
    k = key("HUNTER_API_KEY")
    if not k:
        return {"tool": "hunter.io", "skipped": "no API key", "emails": []}
    st, js, err = http_json("https://api.hunter.io/v2/domain-search",
                            params={"domain": domain, "api_key": k, "limit": 50})
    if st != 200 or not isinstance(js, dict):
        return {"tool": "hunter.io", "skipped": f"HTTP {st} {err}"[:160], "emails": []}
    d = js.get("data") or {}
    return {"tool": "hunter.io", "pattern": d.get("pattern"), "organization": d.get("organization"),
            "emails": [{"value": e.get("value"), "type": e.get("type"),
                        "confidence": e.get("confidence"),
                        "name": " ".join(filter(None, [e.get("first_name"), e.get("last_name")])),
                        "position": e.get("position")}
                       for e in (d.get("emails") or [])]}

def stage_hunter_verify(email):
    k = key("HUNTER_API_KEY")
    if not k:
        return {"tool": "hunter.io", "skipped": "no API key"}
    st, js, err = http_json("https://api.hunter.io/v2/email-verifier",
                            params={"email": email, "api_key": k})
    if st != 200 or not isinstance(js, dict):
        return {"tool": "hunter.io", "skipped": f"HTTP {st} {err}"[:160]}
    d = js.get("data") or {}
    return {"tool": "hunter.io", "status": d.get("status"), "score": d.get("score"),
            "disposable": d.get("disposable"), "webmail": d.get("webmail"),
            "mx_records": d.get("mx_records"), "sources": len(d.get("sources") or [])}

# ---------------- STAGE 5: METADATA ----------------
def _summarize_exif(meta):
    """Summarize top forensic fields: Make/Model/Software/GPS/DateTimeOriginal/Creator."""
    summary = {}
    make = meta.get("Make") or ""
    model = meta.get("Model") or meta.get("CameraModelName") or ""
    lens = meta.get("LensModel") or meta.get("Lens") or meta.get("LensInfo") or ""
    dev_parts = [str(p).strip() for p in (make, model) if str(p).strip()]
    if dev_parts:
        dev_str = " ".join(dev_parts)
        if lens and str(lens).strip() not in dev_str:
            dev_str += f" (Lens: {lens})"
        summary["Device"] = dev_str
    elif lens:
        summary["Device"] = f"Lens: {lens}"

    sw = (meta.get("Software") or meta.get("ProfileSoftwareDescription")
          or meta.get("ProcessingSoftware") or meta.get("HistorySoftwareAgent") or "")
    if sw:
        summary["Software"] = str(sw).strip()

    creator = (meta.get("Artist") or meta.get("Creator") or meta.get("By-line")
               or meta.get("Author") or meta.get("Copyright") or meta.get("OwnerName") or "")
    if creator:
        summary["Creator"] = str(creator).strip()

    dt = (meta.get("DateTimeOriginal") or meta.get("CreateDate")
          or meta.get("DateCreated") or meta.get("ModifyDate") or "")
    if dt:
        summary["DateTime"] = str(dt).strip()

    lat = meta.get("GPSLatitude")
    lon = meta.get("GPSLongitude")
    if lat is not None and lon is not None:
        alt = meta.get("GPSAltitude")
        alt_str = f" (alt: {alt}m)" if alt is not None else ""
        summary["GPS"] = f"{lat}, {lon}{alt_str}"
        summary["GPSLatitude"] = lat
        summary["GPSLongitude"] = lon

    return summary

def _extract_exif_thumbnail(et, fpath):
    """Attempt to extract embedded EXIF thumbnail using exiftool."""
    if not et or not os.path.exists(fpath):
        return None
    for tag in ("-ThumbnailImage", "-PreviewImage", "-JpgFromRaw"):
        rc, raw, _ = run_bytes([et, "-b", tag, fpath], timeout=15)
        if rc == 0 and len(raw) >= 128:
            if raw.startswith(b"\xff\xd8") or raw.startswith(b"\x89PNG"):
                mime = "image/png" if raw.startswith(b"\x89PNG") else "image/jpeg"
                return f"data:{mime};base64," + base64.b64encode(raw).decode("ascii")
    return None

def stage_metadata(fpath):
    if not os.path.exists(fpath):
        return {"tool": "metadata", "file": fpath, "skipped": "file not found"}
    if os.path.isdir(fpath):
        return {"tool": "metadata", "file": fpath,
                "skipped": "this is a directory — give the path of a single file"}
    et = tool("exiftool")
    if et:
        rc, out, err = run([et, "-json", "-n", fpath], timeout=60)
        try:
            data = json.loads(out)
            meta = data[0] if data else {}
            if meta.get("Error"):
                return {"tool": "exiftool", "file": fpath,
                        "skipped": f"exiftool could not read it: {meta['Error']}"}
            meta["_summary"] = _summarize_exif(meta)
            thumb = _extract_exif_thumbnail(et, fpath)
            if thumb:
                meta["_thumbnail"] = thumb
            return {"tool": "exiftool", "file": fpath, "meta": meta,
                    "failed": _fail(rc, err, meta)}
        except Exception:
            pass
    try:
        import exifread  # type: ignore
        with open(fpath, "rb") as f:
            tags = exifread.process_file(f, details=False)
        meta = {str(k): str(v) for k, v in tags.items()}
        meta["_summary"] = _summarize_exif(meta)
        if "JPEGThumbnail" in tags:
            raw = tags["JPEGThumbnail"]
            if isinstance(raw, (bytes, bytearray)) and len(raw) >= 128:
                meta["_thumbnail"] = "data:image/jpeg;base64," + base64.b64encode(raw).decode("ascii")
        return {"tool": "exifread", "file": fpath, "meta": meta}
    except Exception:
        return {"tool": "metadata", "file": fpath, "skipped": "exiftool/exifread missing"}

# ---------------- STAGE: PHONE ----------------
DEFAULT_CC = os.environ.get("OSINT_DEFAULT_CC", "90")   # Turkey (+90)
def normalize_phone(number):
    """Coerce to E.164. A national-format number ("0532 …") must not become "+0532…":
    country code 0 does not exist and numverify would answer valid:false."""
    num = re.sub(r"[^\d+]", "", number)
    if not num:
        return num
    if num.startswith("+"):
        return num
    if num.startswith("00"):          # international prefix
        return "+" + num[2:]
    if num.startswith("0"):           # national trunk prefix -> default country
        return "+" + DEFAULT_CC + num[1:]
    return "+" + num

def stage_numverify(number):
    """numverify (apilayer) — carrier, line type, country. Free plan is HTTP-only."""
    k = key("NUMVERIFY_API_KEY")
    if not k:
        return {"tool": "numverify", "skipped": "no API key"}
    params = {"access_key": k, "number": number.lstrip("+"), "format": 1}
    st, js, err = http_json("https://apilayer.net/api/validate", params=params)
    # No plaintext-HTTP retry: it would put the API key and the target's number on the
    # wire in the clear (ISP, or an untrusted Tor exit).
    if not isinstance(js, dict):
        return {"tool": "numverify", "skipped": f"HTTP {st} {err}"[:160]}
    if js.get("success") is False:
        return {"tool": "numverify", "skipped": str((js.get("error") or {}).get("info", ""))[:160]}
    return {"tool": "numverify", "valid": js.get("valid"),
            "international_format": js.get("international_format"),
            "local_format": js.get("local_format"),
            "country_code": js.get("country_code"), "country_name": js.get("country_name"),
            "location": js.get("location"), "carrier": js.get("carrier"),
            "line_type": js.get("line_type")}

def stage_phoneinfoga(number):
    exe = tool("phoneinfoga")
    if not exe:
        return {"tool": "phoneinfoga", "skipped": "not installed"}
    rc, out, err = run([exe, "scan", "-n", number], timeout=150)
    local = {}
    for m in re.finditer(r"^\s*(Raw local|Local|E164|International|Country|Carrier|Line type|Valid):\s*(.+)$",
                         out, re.M):
        local[m.group(1).strip()] = m.group(2).strip()
    dorks = {"social": [], "disposable": [], "individual": [], "reputation": [], "other": []}
    section = "other"
    for line in out.splitlines():
        ls = line.strip(); low = ls.lower()
        if low.startswith("social media"): section = "social"
        elif low.startswith("disposable"): section = "disposable"
        elif low.startswith("individual"): section = "individual"
        elif low.startswith("reputation"): section = "reputation"
        m = re.match(r"URL:\s*(https?://\S+)", ls)
        if m:
            dorks[section].append(m.group(1))
    return {"tool": "phoneinfoga", "local": local, "dorks": dorks,
            "failed": _fail(rc, err, any(dorks.values()) or local),
            "dork_counts": {k: len(v) for k, v in dorks.items() if v}}

def stage_phone(number, use_api=True):
    num = normalize_phone(number)
    res = {"number": num, "phoneinfoga": stage_phoneinfoga(num)}
    res["numverify"] = stage_numverify(num) if use_api else {"tool": "numverify", "skipped": "--no-api"}
    return res

# ---------------- OPSEC LEDGER ----------------
# Records whose logs this scan ended up in, so the report can say so.
OPSEC_LOG = {"target_hosts": {}, "third_parties": {}, "tools": [], "tor": False}

def _opsec(bucket, host, n=1):
    if not host:
        return
    d = OPSEC_LOG[bucket]
    d[host] = d.get(host, 0) + n

# ---------------- CURATED PIVOTS (OSINT Framework dataset) ----------------
# Rendered as links only, never fetched.
PIVOT_CATS = {
    "username": ["Username", "Social Networks", "Online Communities"],
    "email":    ["Email Address"],
    "domain":   ["Domain Name"],
    "phone":    ["Telephone Numbers"],
    "name":     ["People Search Engines", "Public Records"],
    "image":    ["Images / Videos / Docs"],
}

# Upstream entries that carry a placeholder, plus our own, pre-filled with the target value.
PREFILL = {
    "username": [("Google — exact mentions", 'https://www.google.com/search?q=%22{q}%22'),
                 ("GitHub API — public events (commit e-mails leak here)",
                  "https://api.github.com/users/{q}/events/public"),
                 ("ProtonMail key lookup — is there a proton account?",
                  "https://api.protonmail.ch/pks/lookup?op=index&search={q}@protonmail.com"),
                 ("Wayback — archived copies of this handle",
                  "https://web.archive.org/web/*/{q}*")],
    "email":    [("Google — exact mentions", 'https://www.google.com/search?q=%22{q}%22'),
                 ("ProtonMail key lookup", "https://api.protonmail.ch/pks/lookup?op=index&search={q}"),
                 ("Have I Been Pwned (manual)", "https://haveibeenpwned.com/account/{q}")],
    "domain":   [("crt.sh certificates", "https://crt.sh/?q=%25.{q}"),
                 ("Wayback history", "https://web.archive.org/web/*/{q}/*"),
                 ("Google — indexed subdomains", "https://www.google.com/search?q=site%3A{q}")],
    "phone":    [("Google — exact number", 'https://www.google.com/search?q=%22{q}%22'),
                 ("Numbering Plans analysis",
                  "https://www.numberingplans.com/?page=analysis&sub=phonenr")],
    "name":     [("Google — exact name", 'https://www.google.com/search?q=%22{q}%22'),
                 ("LinkedIn via Google", 'https://www.google.com/search?q=site%3Alinkedin.com%2Fin+%22{q}%22')],
}

_ARF_CACHE = None
def load_arf():
    global _ARF_CACHE
    if _ARF_CACHE is None:
        _ARF_CACHE = []
        f = RESOURCES / "arf.json"
        if f.exists():
            try:
                data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                def walk(node, path=()):
                    if not isinstance(node, dict):
                        return
                    if node.get("children"):
                        for c in node["children"]:
                            walk(c, path + (node.get("name"),))
                    else:
                        _ARF_CACHE.append((path, node))
                walk(data)
            except Exception:
                pass
    return _ARF_CACHE

# The dataset writes its tokens both bare (<username>) and percent-encoded
# (%3Cusername%3E), depending on whether the upstream entry stored a query string.
ARF_PH_RE = re.compile(r"<[a-z_.]{2,30}>|%3C[a-z_.]{2,30}%3E", re.I)

def _fill_placeholders(url, value):
    """Substitute the ARF dataset's own <username>/<email_address>/… tokens.

    Returns (url, filled) so a template we cannot fill can be dropped rather than shown."""
    from urllib.parse import quote
    if not ARF_PH_RE.search(url):
        return url, False
    return ARF_PH_RE.sub(quote(str(value), safe=""), url), True

def pivots_for(kind, limit=10, value=None):
    """Curated, live, link-only resources for one entity type — passive and free first."""
    cats = PIVOT_CATS.get(kind, [])
    out, seen = [], set()
    for path, leaf in load_arf():
        if len(path) < 2 or path[1] not in cats:
            continue
        if leaf.get("type") != "url" or leaf.get("deprecated") or leaf.get("status") != "live":
            continue
        if leaf.get("localInstall") or not (leaf.get("url") or "").startswith("http"):
            continue
        url, filled = _fill_placeholders(leaf["url"], value)
        if filled and value is None:
            continue                      # a template we have no value for is a dead link
        k = url.rstrip("/").lower()
        if k in seen:                     # the dataset repeats some URLs within one kind
            continue
        seen.add(k)
        out.append({"name": leaf.get("name"), "url": url, "prefilled": filled,
                    "opsec": (leaf.get("opsec") or "unknown").lower(),
                    "note": leaf.get("opsecNote") or "",
                    "desc": leaf.get("description") or "",
                    "pricing": leaf.get("pricing") or "",
                    "reg": bool(leaf.get("registration")),
                    "cat": path[1]})
    rank = {"passive": 0, "unknown": 1, "active": 2}
    # Prefilled first, then free: without a tie-break the sort falls through to the name.
    out.sort(key=lambda x: (rank.get(x["opsec"], 1),
                            0 if x["prefilled"] else 1,
                            0 if str(x["pricing"]).startswith("free") else 1,
                            x["reg"], x["name"] or ""))
    return out[:limit]

def prefilled(kind, value):
    from urllib.parse import quote
    q = quote(str(value), safe="")
    return [{"name": n, "url": u.replace("{q}", q)} for n, u in PREFILL.get(kind, [])]

def reverse_image_links(img_url):
    """Reverse image search links for a captured avatar."""
    from urllib.parse import quote
    e = quote(img_url, safe="")
    return [("Google Lens", f"https://lens.google.com/uploadbyurl?url={e}"),
            ("Yandex Images", f"https://yandex.com/images/search?rpt=imageview&url={e}"),
            ("Bing Visual Search", f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{e}"),
            ("TinEye", f"https://tineye.com/search?url={e}")]

def local_image_search_links():
    """Direct search portal links for a local target image (manual upload / drag & drop)."""
    return [("Google Lens", "https://lens.google.com/"),
            ("Yandex Images", "https://yandex.com/images/"),
            ("Bing Visual Search", "https://www.bing.com/images/search?view=detailv2&iss=sbi"),
            ("TinEye", "https://tineye.com/")]

# ---------------- STAGE: INSTAGRAM PROFILE (instaloader) ----------------
# Anonymous requests get 429; needs a session file (instaloader --login=<burner>) or it skips.
IG_PY = OSINT / "pipx" / "venvs" / "instaloader" / "bin" / "python"

IG_PROBE = r"""
import json, sys, glob, os
import instaloader
L = instaloader.Instaloader(quiet=True, download_pictures=False, download_videos=False,
                            download_comments=False, save_metadata=False,
                            max_connection_attempts=1, request_timeout=15.0)
used_session = None
for f in sorted(glob.glob(os.path.expanduser("~/.config/instaloader/session-*"))):
    try:
        L.load_session_from_file(os.path.basename(f).replace("session-", ""), f)
        used_session = os.path.basename(f).replace("session-", "")
        break
    except Exception:
        pass
try:
    p = instaloader.Profile.from_username(L.context, sys.argv[1])
    print(json.dumps({"ok": True, "session": used_session, "username": p.username,
                      "full_name": p.full_name, "biography": p.biography,
                      "external_url": p.external_url, "followers": p.followers,
                      "followees": p.followees, "is_private": p.is_private,
                      "is_verified": p.is_verified, "is_business": p.is_business_account,
                      "business_category": p.business_category_name,
                      "profile_pic_url": p.profile_pic_url, "userid": p.userid},
                     ensure_ascii=False))
except Exception as e:
    print(json.dumps({"ok": False, "session": used_session,
                      "error": (type(e).__name__ + ": " + str(e))[:200]}))
"""

def stage_instagram(username, use_tor=False):
    if not IG_PY.exists():
        return {"tool": "instaloader", "ok": False, "skipped": "instaloader not installed"}
    _opsec("target_hosts", "instagram.com")
    rc, out, err = run([str(IG_PY), "-c", IG_PROBE, username], timeout=90, use_tor=use_tor)
    for line in reversed(out.strip().splitlines()):
        try:
            d = json.loads(line)
            d["tool"] = "instaloader"
            if not d.get("ok"):
                e = d.get("error", "")
                if "429" in e:
                    d["skipped"] = ("Instagram answered 429 to an anonymous request. Log in once "
                                    "with a throwaway account (instaloader --login=<burner>) and "
                                    "this stage starts working.")
                elif "404" in e or "does not exist" in e:
                    d["skipped"] = "no such Instagram account"
                else:
                    d["skipped"] = e
            return d
        except Exception:
            continue
    return {"tool": "instaloader", "ok": False, "skipped": (err or out or "no output").strip()[:160]}

def enrich_instagram(findings, usernames, use_tor=False, fetch_avatar=True):
    """Query Instagram for each candidate handle and fold the result into the account list."""
    res = {}
    for u in usernames:
        r = stage_instagram(u, use_tor=use_tor)
        if r.get("ok") and fetch_avatar and r.get("profile_pic_url"):
            th = _thumb([r["profile_pic_url"]])
            r["avatar"], r["avatar_hash"], r["avatar_src"], r["avatar_sha256"] = th
            r["avatar_hashes"] = getattr(th, "hashes", {})
            r["avatar_is_generated"] = getattr(th, "is_generated", False)
            r["avatar_file"] = _save_image(r["avatar_sha256"], getattr(th, "hd", b""))
        res[u] = r
        if not r.get("ok"):
            continue
        rows = findings.get("verified") or []
        row = next((x for x in rows if _host(x.get("url")) == "instagram.com"
                    and _slug(x.get("user")) == _slug(u)), None)
        if row is None:
            row = {"site": "Instagram", "url": f"https://www.instagram.com/{u}/", "user": u,
                   "via": ["instaloader"], "state": "verified", "status": 200}
            rows.append(row)
            findings["verified"] = rows
        row["display_name"] = r.get("full_name") or row.get("display_name") or ""
        row["description"] = r.get("biography") or row.get("description") or ""
        if r.get("avatar"):
            row["avatar"], row["avatar_hash"] = r["avatar"], r["avatar_hash"]
            row["avatar_src"] = r.get("avatar_src")
            row["avatar_sha256"] = r.get("avatar_sha256")
            row["avatar_hashes"] = r.get("avatar_hashes", {})
            row["avatar_is_generated"] = r.get("avatar_is_generated", False)
            if r.get("avatar_file"):
                row["avatar_file"] = r["avatar_file"]
        extra = [x for x in (r.get("business_email"),) if x]
        row["emails"] = sorted(set((row.get("emails") or []) + extra))
    findings["instagram"] = res
    return res

# ---------------- STAGE: ACCOUNT VERIFICATION & PROFILE ENRICHMENT ----------------
# Every discovered URL is fetched and checked for the handle in its visible text.
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

DEAD_MARKERS = ("page not found", "not found", "page isn't available", "page isn\u2019t available",
                "doesn't exist", "doesn\u2019t exist", "no longer available", "user not found",
                "account suspended", "sorry, this page", "profile not found", "nothing here",
                "content unavailable", "this account doesn", "page doesn")

# Challenge interstitials load with HTTP 200; treat as blocked, never as a real name.
BOT_MARKERS = ("just a moment", "attention required", "checking your browser",
               "not a bot", "verify you are human", "are you a robot", "ddos-guard",
               "captcha", "cloudflare", "enable javascript and cookies", "access denied",
               "security check", "request blocked")

# Consent walls answer 200 with the URL intact, and the URL was built from the handle, so
# it is no evidence. Matched against the <title> only: the bio is the subject's own text.
INTERSTITIAL_TITLES = ("before you continue", "sign in to confirm", "just a moment",
                       "attention required", "checking your browser", "verify you are human",
                       "are you a robot", "enable javascript", "access denied",
                       "security check", "captcha", "request blocked", "unusual traffic")

STATE_ORDER = {"verified": 0, "unconfirmed": 1, "blocked": 2, "unknown": 3, "dead": 4, "error": 5}
STATE_LABEL = {"verified": "verified", "unconfirmed": "could not confirm", "blocked": "blocked by site",
               "unknown": "unknown", "dead": "does not exist", "error": "unreachable from here"}
# error is not a false positive: SSL/DNS failures usually mean ISP blocking; re-run over Tor.

def _meta(doc, prop):
    """Read one <meta> value. Bounded patterns only: a greedy .*? backtracks for minutes on big pages."""
    for pat in (r'<meta[^>]{0,400}?(?:property|name)\s*=\s*["\']%s["\'][^>]{0,400}?content\s*=\s*["\']([^"\']{0,600})',
                r'<meta[^>]{0,400}?content\s*=\s*["\']([^"\']{0,600})["\'][^>]{0,400}?(?:property|name)\s*=\s*["\']%s["\']'):
        m = re.search(pat % re.escape(prop), doc, re.I)
        if m:
            return html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:400]
    return ""

def _display_name(title, ogtitle, username, site=""):
    """Pull a human name out of the page title: 'user (Real Name) - Site' -> 'Real Name'."""
    us, sn = _slug(username), _slug(site)
    STOP = {"profile", "home", "login", "signin", "signup", "page", "user", "account",
            "overview", "contact", "channel", "welcome"}
    # Interstitials answer 200 with a sentence-like title ("Before you continue to YouTube").
    STOP_PHRASES = ("before you continue", "sign in", "log in", "consent", "cookie",
                    "privacy", "enable javascript", "just a moment", "are you", "verify",
                    "redirecting", "loading", "access denied", "not found", "error",
                    # Soft-404 titles. A denylist can never be complete; the allowlist
                    # below does the real work.
                    "deleted", "suspended", "unavailable", "no longer", "removed", "banned",
                    "doesn't exist", "does not exist", "forbidden", "restricted",
                    "oops", "whoops", "sorry,", "page isn", "this page", "temporarily",
                    "bulunamad", "bulamad", "kaldırıl", "askıya")

    def usable(cand):
        c = (cand or "").strip()
        sl = _slug(c)
        low = c.lower()
        if not c or not (2 <= len(c) <= 50) or not sl or c.isdigit():
            return False
        if sl in STOP or (sn and sl == sn):
            return False
        if any(ph in low for ph in STOP_PHRASES):
            return False
        if sl == us:
            # The name spelled out; reject the bare handle or a leading sigil only.
            core = re.sub(r"^[^a-z0-9]+|[^a-z0-9]+$", "", low)
            return (bool(re.search(r"[a-z0-9][^a-z0-9][a-z0-9]", core))
                    and core != (username or "").lower())
        if us and us in sl:
            return False      # handle sitting among other words: "Telegram: Contact @user"
        return True

    for cand in (ogtitle, title):
        if not cand:
            continue
        m = re.search(r"\(([^)]{2,40})\)", cand)
        if m and usable(m.group(1)):
            return m.group(1).strip()
    for cand in (ogtitle, title):
        if not cand:
            continue
        part = re.split(r"\s[\u00b7|\-\u2013\u2014:]\s", cand)[0]
        part = re.sub(r"\s*\([^)]*\)", "", part).strip()
        if usable(part):
            return part
    return ""

# Generic filenames/patterns for placeholder avatars and icons
GENERIC_FILENAMES = {
    "default.png", "default.jpg", "default.jpeg", "default.gif", "default.svg", "default.webp",
    "placeholder.png", "placeholder.jpg", "placeholder.jpeg", "placeholder.svg",
    "noavatar.png", "no-avatar.png", "no_avatar.png", "noavatar.jpg", "no_avatar.jpg",
    "avatar.png", "avatar.jpg", "avatar.svg", "user.png", "user.jpg", "user.svg",
    "blank.png", "blank.jpg", "anonymous.png", "anonymous.jpg", "favicon.ico",
    "thumb_default.png", "thumb_default.jpg"
}

GENERIC_FILENAME_PATTERNS = (
    "default_avatar", "default-avatar", "defaultavatar",
    "noavatar", "no-avatar", "no_avatar",
    "avatar-default", "avatar_default",
    "profile-default", "profile_default",
    "placeholder-avatar", "placeholder_avatar",
    "thumb_default", "sprite", "favicon", "apple-touch-icon", "apple_touch_icon",
    "share-card", "og-image", "og_image", "opengraph"
)

def _is_generic_avatar_url(url):
    """Check if the image filename looks like a generic placeholder rather than a user avatar.
    Only checks the filename/basename to avoid rejecting valid avatar paths that contain
    words like 'share', 'default', or 'logo' in their directory structure."""
    if not url:
        return True
    try:
        parsed = urllib.parse.urlparse(url)
        fname = posixpath.basename(parsed.path or "").lower().split("?")[0]
        if not fname:
            return False
        if fname in GENERIC_FILENAMES:
            return True
        if any(p in fname for p in GENERIC_FILENAME_PATTERNS):
            return True
        stem = posixpath.splitext(fname)[0]
        return stem in ("default", "logo", "placeholder", "blank", "anonymous", "generic", "dummy")
    except Exception:
        return False

def _avatar_candidates(doc, url="", site="", user=""):
    """Ordered candidate URLs for the profile picture and cover/banner, best first.
    Extracts from site-specific endpoints, JSON-LD, microdata, link rel, meta tags,
    lazy-load attributes, srcset, inline styles, and img tags."""
    out = []
    s_low = (site or "").lower()
    u_low = (url or "").lower()

    # 1. Site-specific high-confidence extractors for frequent platforms
    if "github" in s_low or "github.com" in u_low:
        for m in re.finditer(r"https?://avatars\.githubusercontent\.com/u/\d+[^\"\'\s<>]*", doc):
            out.append(m.group(0))
        for m in re.finditer(r"https?://avatars\.githubusercontent\.com/[^\"\'\s<>\?]+", doc):
            out.append(m.group(0))
        if user:
            out.append(f"https://github.com/{user}.png")

    if "telegram" in s_low or "t.me" in u_low:
        for m in re.finditer(r'<img[^>]+class=["\'][^"\']*tgme_page_photo_image[^"\']*["\'][^>]+src=["\']([^"\']+)["\']', doc, re.I):
            out.append(m.group(1))
        for m in re.finditer(r"https?://(?:cdn\d*\.)?telesco\.pe/file/[^\"\'\s<>]+", doc):
            out.append(m.group(0))

    if "chess" in s_low or "chess.com" in u_low:
        for m in re.finditer(r"https?://images\.chesscomfiles\.com/uploads/v1/user/\d+[^\"\'\s<>]*", doc):
            out.append(m.group(0))

    if "tradingview" in s_low or "tradingview.com" in u_low:
        for m in re.finditer(r"https?://s3\.tradingview\.com/userpics/[^\"\'\s<>]+", doc):
            out.append(m.group(0))
        for m in re.finditer(r"https?://tradingview\.com/userpics/[^\"\'\s<>]+", doc):
            out.append(m.group(0))

    if "youtube" in s_low or "youtube.com" in u_low:
        for m in re.finditer(r"https?://yt3\.ggpht\.com/[^\"\'\s<>]+", doc):
            out.append(m.group(0))

    if "gitlab" in s_low or "gitlab.com" in u_low:
        for m in re.finditer(r"https?://gitlab\.com/uploads/-/system/user/avatar/[^\"\'\s<>]+", doc):
            out.append(m.group(0))

    if "steam" in s_low or "steamcommunity" in u_low:
        for m in re.finditer(r"https?://avatars\.(?:steamstatic|akamai\.steamstatic)\.com/[^\"\'\s<>]+", doc):
            out.append(m.group(0))

    if "medium" in s_low or "medium.com" in u_low:
        for m in re.finditer(r"https?://cdn-images-1\.medium\.com/[^\"\'\s<>]+", doc):
            out.append(m.group(0))
        for m in re.finditer(r"https?://miro\.medium\.com/v2/resize:fill:[^\"\'\s<>]+", doc):
            out.append(m.group(0))

    if "gravatar" in s_low or "gravatar.com" in u_low:
        for m in re.finditer(r"https?://(?:secure\.)?gravatar\.com/avatar/[a-f0-9]{32,64}", doc, re.I):
            out.append(m.group(0))

    # 2. JSON-LD (application/ld+json)
    for m in re.finditer(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', doc, re.I | re.S):
        block = m.group(1).strip()
        try:
            data = json.loads(block)
            def scan_json(obj):
                if isinstance(obj, dict):
                    img = obj.get("image") or obj.get("logo")
                    if isinstance(img, str):
                        out.append(img)
                    elif isinstance(img, dict) and img.get("url"):
                        out.append(img["url"])
                    elif isinstance(img, list):
                        for item in img:
                            if isinstance(item, str): out.append(item)
                            elif isinstance(item, dict) and item.get("url"): out.append(item["url"])
                    for v in obj.values():
                        scan_json(v)
                elif isinstance(obj, list):
                    for item in obj: scan_json(item)
            scan_json(data)
        except Exception:
            for img_match in re.finditer(r'"(?:image|contentUrl)"\s*:\s*"(https?://[^"]+)"', block):
                out.append(img_match.group(1))

    # 3. Microdata (itemprop="image")
    for pat in (r'<[^>]+itemprop=["\']image["\'][^>]+(?:src|content)=["\']([^"\']+)["\']',
                r'<[^>]+(?:src|content)=["\']([^"\']+)["\'][^>]+itemprop=["\']image["\']'):
        for m in re.finditer(pat, doc, re.I):
            out.append(m.group(1))

    # 4. Link rel="image_src". apple-touch-icon is deliberately excluded: it is the site's
    # own icon, it is square so it clears the shape gate, and ranking above og:image it
    # became "the avatar" on any page that declares one.
    for pat in (r'<link[^>]+rel=["\']image_src["\'][^>]+href=["\']([^"\']+)["\']',
                r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']image_src["\']'):
        for m in re.finditer(pat, doc, re.I):
            out.append(m.group(1))

    # 5. OpenGraph and Twitter
    for prop in ("og:image", "twitter:image", "twitter:image:src"):
        v = _meta(doc, prop)
        if v:
            out.append(v)

    # 6. Lazy-load & srcset
    for pat in (r'<img[^>]+(?:class|id)=["\'][^"\']*(?:avatar|profile|user|author)[^"\']*["\'][^>]+(?:data-src|data-original|data-lazy-src|data-highres)=["\']([^"\']+)["\']',
                r'<img[^>]+(?:data-src|data-original|data-lazy-src|data-highres)=["\']([^"\']+)["\'][^>]+(?:class|id)=["\'][^"\']*(?:avatar|profile|user|author)'):
        for m in re.finditer(pat, doc, re.I):
            out.append(m.group(1))
    for m in re.finditer(r'<img[^>]+(?:class|id)=["\'][^"\']*(?:avatar|profile|user)[^"\']*["\'][^>]+srcset=["\']([^"\']+)["\']', doc, re.I):
        for part in m.group(1).split(","):
            cand_url = part.strip().split()[0]
            if cand_url:
                out.append(cand_url)

    # 7. Inline background-image on avatar elements
    for pat in (r'<[^>]+(?:class|id)=["\'][^"\']*(?:avatar|profile|user-photo|user-img|author-thumb)[^"\']*["\'][^>]+style=["\'][^"\']*background(?:-image)?:\s*url\(["\']?([^"\'\)]+)["\']?\)',
                r'<[^>]+style=["\'][^"\']*background(?:-image)?:\s*url\(["\']?([^"\'\)]+)["\']?\)[^>]+(?:class|id)=["\'][^"\']*(?:avatar|profile|user-photo|user-img|author-thumb)'):
        for m in re.finditer(pat, doc, re.I):
            out.append(m.group(1))

    # 8. Standard img with avatar class/id
    for pat in (r'<img[^>]{0,300}?(?:class|id)=["\'][^"\']{0,140}avatar[^"\']{0,140}["\'][^>]{0,300}?src=["\'](https?://[^"\']{5,400})',
                r'<img[^>]{0,300}?src=["\'](https?://[^"\']{5,400})["\'][^>]{0,300}?(?:class|id)=["\'][^"\']{0,140}avatar'):
        for m in re.finditer(pat, doc, re.I):
            out.append(m.group(1))

    seen, res = set(), []
    for raw_u in out:
        u = html.unescape(raw_u or "").strip().strip("\"'")
        if not u:
            continue
        if u.startswith("//"):
            u = "https:" + u
        elif url and (u.startswith("/") or not u.startswith(("http://", "https://"))):
            u = urllib.parse.urljoin(url, u)
        if not u.startswith(("http://", "https://")):
            continue
        if not _is_generic_avatar_url(u) and u not in seen:
            seen.add(u)
            res.append(u)
    return res[:12]

def _read_capped(resp, cap):
    """Body bytes, or None once it exceeds cap. Closes the connection either way.

    requests materialises the whole body before any size check, so a hostile page could
    stream gigabytes into RAM across all verify workers."""
    buf = bytearray()
    try:
        for chunk in resp.iter_content(65536):
            buf += chunk
            if len(buf) > cap:
                return None
        return bytes(buf)
    except Exception:
        return None
    finally:
        resp.close()

def _dhash(im, s=8):
    """Perceptual difference hash — same picture on two sites gives (almost) the same value."""
    from PIL import Image as _I
    g = im.convert("L").resize((s + 1, s), _I.Resampling.LANCZOS)
    px = g.tobytes()
    bits = 0
    for r in range(s):
        row = r * (s + 1)
        for c in range(s):
            bits = (bits << 1) | (1 if px[row + c] > px[row + c + 1] else 0)
    return bits

_N_PHASH = 32
_COS_TABLE = [[math.cos((2 * x + 1) * u * math.pi / (2 * _N_PHASH)) for x in range(_N_PHASH)] for u in range(8)]

def _phash(im):
    """64-bit DCT-based perceptual hash (pHash).
    Pure-Python implementation with zero external dependencies (no numpy, no scipy).
    Resizes image to 32x32 grayscale, computes lowest 8x8 2D DCT-II coefficients,
    and sets bits based on median threshold of AC coefficients."""
    from PIL import Image as _I
    g = im.convert("L").resize((_N_PHASH, _N_PHASH), _I.Resampling.LANCZOS)
    px = list(g.tobytes())
    row_dct = [[0.0] * _N_PHASH for _ in range(8)]
    for u in range(8):
        c_u = _COS_TABLE[u]
        for y in range(_N_PHASH):
            offset = y * _N_PHASH
            row_dct[u][y] = sum(px[offset + x] * c_u[x] for x in range(_N_PHASH))
    dct = []
    for u in range(8):
        for v in range(8):
            c_v = _COS_TABLE[v]
            dct.append(sum(row_dct[u][y] * c_v[y] for y in range(_N_PHASH)))
    # Median over the AC coefficients only, as the reference implementation does. dct[0] (DC)
    # then always lands above it, so bit 63 is constant and the hash carries 63 usable bits.
    ac = dct[1:]
    med = sorted(ac)[31]
    bits = 0
    for val in dct:
        bits = (bits << 1) | (1 if val > med else 0)
    return bits

def _is_generated_avatar(im):
    """Detect default/letter/initials avatars (e.g. colored circle with 'AG' or 1-2 letters).
    These produce identical or near-identical hashes for completely unrelated people.
    Signals:
      1) Discrete dominant color count <= 3 (accounting for >= 96% of pixels)
      2) Low grayscale variance (uniform flat background) or minimal discrete palette."""
    try:
        from PIL import ImageStat, Image as _I
        small = im.convert("RGB").resize((64, 64), _I.Resampling.NEAREST)
        q = small.quantize(colors=16)
        colors = q.getcolors() or []
        colors.sort(reverse=True, key=lambda x: x[0])
        total_px = 64 * 64
        cum = 0
        dom_count = 0
        for count, _ in colors:
            cum += count
            dom_count += 1
            if cum / total_px >= 0.96:
                break
        stat = ImageStat.Stat(small.convert("L"))
        var = stat.var[0] if stat.var else 0
        if dom_count <= 2:
            return True
        if dom_count <= 3 and (var < 800 or (cum / total_px >= 0.98)):
            return True
        return False
    except Exception:
        return False

class ThumbResult(tuple):
    """4-tuple (data_uri, hash_hex, url, sha256) plus perceptual hashes, the generated-avatar
    flag, a discovered cover image and `hd`, a face-grade JPEG copy for the vision stage."""
    def __new__(cls, data_uri="", hash_hex="", url="", sha256="", hashes=None, is_generated=False, cover=None, hd=b""):
        return super().__new__(cls, (data_uri, hash_hex, url, sha256))

    def __init__(self, data_uri="", hash_hex="", url="", sha256="", hashes=None, is_generated=False, cover=None, hd=b""):
        self.hashes = hashes or {}
        self.is_generated = is_generated
        self.cover = cover or {}
        self.hd = hd

def _jpeg_copy(im, px, quality):
    c = im.convert("RGB")
    c.thumbnail((px, px))
    buf = io.BytesIO()
    c.save(buf, "JPEG", quality=quality)
    return buf.getvalue()

def _watermark(data_uri, text=DISPUTED_MARK, px=220):
    """Stamp a caption band on a thumbnail so a disputed picture cannot be read as evidence.

    Returns the original URI unchanged if anything fails: losing the picture would be worse
    than losing the mark."""
    if not (data_uri or "").startswith("data:image"):
        return data_uri
    try:
        from PIL import Image as _I, ImageDraw, ImageFont
        im = _I.open(io.BytesIO(base64.b64decode(data_uri.split(",", 1)[1]))).convert("RGB")
        if im.width < px:
            im = im.resize((px, max(1, round(im.height * px / im.width))), _I.Resampling.LANCZOS)
        d = ImageDraw.Draw(im)
        size = max(9, im.width // 13)
        font = ImageFont.load_default(size=size)
        while size > 8 and d.textlength(text, font=font) > im.width - 8:
            size -= 1
            font = ImageFont.load_default(size=size)
        band = size + 9
        d.rectangle([0, im.height - band, im.width, im.height], fill=(172, 28, 28))
        d.rectangle([0, 0, im.width - 1, im.height - 1], outline=(172, 28, 28),
                    width=max(2, im.width // 45))
        d.text(((im.width - d.textlength(text, font=font)) / 2, im.height - band + 4),
               text, font=font, fill=(255, 255, 255))
        buf = io.BytesIO()
        im.save(buf, "JPEG", quality=82)
        return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return data_uri

def _save_image(sha, blob):
    """Keep a picture under <case>/images/ for the vision stage; "" when no case folder is set."""
    if not (IMAGES_DIR and blob and sha):
        return ""
    try:
        IMAGES_DIR.mkdir(parents=True, exist_ok=True)
        f = IMAGES_DIR / f"{sha[:16]}.jpg"
        if not f.exists():
            f.write_bytes(blob)
        return f"images/{f.name}"
    except OSError:
        return ""

def _fetch_target_ok(url):
    """Refuse to fetch anything that is not a public http(s) host.

    Avatar URLs come from a page the subject controls (SSRF: localhost, cloud metadata,
    LAN). Over Tor the name resolves at the exit, so the address check is skipped there."""
    from urllib.parse import urlparse
    try:
        u = urlparse(url)
    except Exception:
        return False
    if u.scheme not in ("http", "https") or not u.hostname:
        return False
    host = u.hostname.lower()
    if host in ("localhost",) or host.endswith(".localhost") or host.endswith(".local"):
        return False
    if USE_TOR:
        return True
    import ipaddress, socket
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return False
    return True

_THUMB_CACHE, _THUMB_LOCK = {}, threading.Lock()

def _thumb_one(url, px, timeout):
    """One candidate URL -> ThumbResult, dict for cover, or None.
    Memoised, failures included: several rows of one scan share an avatar."""
    with _THUMB_LOCK:
        if url in _THUMB_CACHE:
            return _THUMB_CACHE[url]
    res = None
    try:
        if not _fetch_target_ok(url):
            raise ValueError("not a public http(s) host")
        import warnings
        from PIL import Image
        import requests
        _opsec("target_hosts", _host(url))
        r = requests.get(url, headers={"User-Agent": BROWSER_UA}, timeout=timeout,
                         proxies=PROXIES, stream=True)
        if r.status_code == 200:
            blob = _read_capped(r, 8_000_000)   # None when oversized: a hostile host must not fill RAM
            if blob is not None:
                Image.MAX_IMAGE_PIXELS = 40_000_000
                with warnings.catch_warnings():
                    warnings.simplefilter("error", Image.DecompressionBombWarning)
                    im = Image.open(io.BytesIO(blob))
                    im.load()
                w, h = im.size
                sha = hashlib.sha256(blob).hexdigest()
                is_avatar = (w >= 48 and h >= 48 and 0.75 <= w / h <= 1.34)
                is_cover = (w >= 200 and h >= 60 and (w / h >= 1.4 or w / h <= 0.65))

                if is_avatar:
                    hsh_d = _dhash(im)
                    hsh_p = _phash(im)
                    # Center crop (85% inner area)
                    cw, ch = max(16, int(w * 0.85)), max(16, int(h * 0.85))
                    cx, cy = (w - cw) // 2, (h - ch) // 2
                    im_center = im.crop((cx, cy, cx + cw, cy + ch))
                    hsh_dc = _dhash(im_center)
                    hsh_pc = _phash(im_center)

                    is_gen = _is_generated_avatar(im)
                    hashes = {
                        "dhash": hsh_d,
                        "dhash_center": hsh_dc,
                        "phash": hsh_p,
                        "phash_center": hsh_pc,
                    }
                    data_uri = "data:image/jpeg;base64," + base64.b64encode(_jpeg_copy(im, px, 78)).decode()
                    # 72 px is enough for the report; face embeddings need the larger copy.
                    res = ThumbResult(data_uri, f"{hsh_d:016x}", url, sha,
                                      hashes=hashes, is_generated=is_gen, hd=_jpeg_copy(im, 320, 85))
                elif is_cover:
                    im_cov = im.convert("RGB")
                    im_cov.thumbnail((240, 120))
                    buf = io.BytesIO()
                    im_cov.save(buf, "JPEG", quality=75)
                    cov_uri = "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()
                    res = {"kind": "cover", "url": url, "sha256": sha, "data_uri": cov_uri}
        else:
            r.close()
    except Exception:
        res = None
    with _THUMB_LOCK:
        _THUMB_CACHE[url] = res
    return res

def _thumb(urls, px=72, timeout=12):
    """Fetch the first URL that qualifies as a profile picture, plus cover/banner if seen.
    Returns ThumbResult — empty strings when nothing qualified."""
    if isinstance(urls, str):
        urls = [urls]
    avatar_res = None
    cover_res = None
    for url in urls:
        if _is_generic_avatar_url(url):
            continue
        res = _thumb_one(url, px, timeout)
        if not res:
            continue
        if isinstance(res, ThumbResult) and not avatar_res:
            avatar_res = res
            if cover_res:
                break
        elif isinstance(res, dict) and res.get("kind") == "cover" and not cover_res:
            cover_res = res
            if avatar_res:
                break
    if avatar_res:
        if cover_res:
            avatar_res.cover = cover_res
        return avatar_res
    return ThumbResult("", "", "", "", cover=cover_res or {})

def process_target_image(path_or_url, px=140, timeout=15):
    """Process an operator-supplied target reference image (local path or remote URL).
    Returns a dict with hashes, thumbnail data URI, dimensions, and reverse search links."""
    path_or_url = str(path_or_url).strip()
    is_url = path_or_url.startswith("http://") or path_or_url.startswith("https://")
    blob = None
    filename = ""

    if is_url:
        filename = posixpath.basename(urllib.parse.urlsplit(path_or_url).path) or path_or_url
        try:
            if not _fetch_target_ok(path_or_url):
                return {"error": "not a public http(s) host", "source": path_or_url, "filename": filename}
            import requests
            _opsec("target_hosts", _host(path_or_url))
            r = requests.get(path_or_url, headers={"User-Agent": BROWSER_UA},
                             timeout=timeout, proxies=PROXIES, stream=True)
            if r.status_code == 200:
                blob = _read_capped(r, 8_000_000)
            else:
                r.close()
                return {"error": f"HTTP {r.status_code}", "source": path_or_url, "filename": filename}
        except Exception as e:
            return {"error": f"fetch failed: {type(e).__name__}", "source": path_or_url, "filename": filename}
    else:
        p = pathlib.Path(path_or_url).expanduser().resolve()
        filename = p.name
        if not p.exists():
            return {"error": f"file not found: {p}", "source": path_or_url, "filename": filename}
        try:
            sz = p.stat().st_size
            if sz > 15_000_000:
                return {"error": f"file exceeds 15MB limit ({sz} bytes)", "source": path_or_url, "filename": filename}
            blob = p.read_bytes()
        except Exception as e:
            return {"error": f"read error: {type(e).__name__}", "source": path_or_url, "filename": filename}

    if blob is None:
        return {"error": "empty image data", "source": path_or_url, "filename": filename}

    try:
        import warnings
        from PIL import Image as _I
        _I.MAX_IMAGE_PIXELS = 40_000_000
        with warnings.catch_warnings():
            warnings.simplefilter("error", _I.DecompressionBombWarning)
            im = _I.open(io.BytesIO(blob))
            im.load()
        w, h = im.size
        sha = hashlib.sha256(blob).hexdigest()

        hsh_d = _dhash(im)
        hsh_p = _phash(im)
        # Center crop (85% inner area)
        cw, ch = max(16, int(w * 0.85)), max(16, int(h * 0.85))
        cx, cy = (w - cw) // 2, (h - ch) // 2
        im_center = im.crop((cx, cy, cx + cw, cy + ch))
        hsh_dc = _dhash(im_center)
        hsh_pc = _phash(im_center)

        is_gen = _is_generated_avatar(im)
        hashes = {
            "dhash": hsh_d,
            "dhash_center": hsh_dc,
            "phash": hsh_p,
            "phash_center": hsh_pc,
        }
        im_thumb = im.convert("RGB")
        im_thumb.thumbnail((px, px), _I.Resampling.LANCZOS)
        buf = io.BytesIO()
        im_thumb.save(buf, "JPEG", quality=82)
        data_uri = "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()

        rev_links = reverse_image_links(path_or_url) if is_url else local_image_search_links()
        hd_file = _save_image(sha, _jpeg_copy(im, 640, 88))

        return {
            "source": path_or_url,
            "filename": filename,
            "is_url": is_url,
            "hd_file": hd_file,
            "sha256": sha,
            "avatar_sha256": sha,
            "avatar_hash": f"{hsh_d:016x}",
            "avatar_hashes": hashes,
            "avatar_is_generated": is_gen,
            "thumb": data_uri,
            "dimensions": f"{w}×{h}",
            "reverse_links": rev_links,
            "matches": [],
        }
    except Exception as e:
        return {"error": f"image decode failed: {type(e).__name__}", "source": path_or_url, "filename": filename}

def match_target_images_against_accounts(target_images, accounts, max_dist=6, max_phash=8):
    """Compare operator-supplied target images against verified accounts' avatars and covers.
    Populates target_image['matches'] with matched account summaries."""
    for timg in target_images:
        if not timg or timg.get("error"):
            continue
        matches = []
        for acc in accounts:
            if not acc:
                continue
            # Compare with avatar
            if acc.get("avatar_hash") or acc.get("avatar_sha256"):
                matched, tier = _images_match(timg, acc, max_dhash=max_dist, max_phash=max_phash)
                if matched:
                    matches.append({
                        "site": acc.get("site") or "?",
                        "user": acc.get("user") or "",
                        "url": acc.get("url") or "",
                        "display_name": acc.get("display_name") or "",
                        "tier": tier,
                        "avatar": acc.get("avatar") or "",
                        "avatar_src": acc.get("avatar_src") or "",
                        "kind": "avatar",
                    })
                    acc["target_image_match"] = tier
                    continue
            # Compare with cover if cover has sha256
            if acc.get("cover_sha256") and acc["cover_sha256"] == timg.get("sha256"):
                matches.append({
                    "site": acc.get("site") or "?",
                    "user": acc.get("user") or "",
                    "url": acc.get("url") or "",
                    "display_name": acc.get("display_name") or "",
                    "tier": "strong",
                    "avatar": acc.get("cover_thumb") or "",
                    "avatar_src": acc.get("cover_url") or "",
                    "kind": "cover",
                })
                acc["target_image_match"] = "strong"
        timg["matches"] = matches

MATCH_TIER_ORDER = {"strong": 0, "face": 1, "possible": 2, "similar": 3}

def _vision_call(doc, extra, timeout=1800):
    """One ml/vision.py subprocess. Returns the parsed result or {"status": "failed"}."""
    cmd = [str(ML_PY), str(VISION_PY), "analyze", "-"] + extra
    try:
        p = subprocess.run(cmd, input=json.dumps(doc, default=str), capture_output=True,
                           text=True, timeout=timeout)
    except Exception as e:
        return {"status": "failed", "reason": type(e).__name__}
    try:
        res = json.loads(p.stdout)
    except ValueError:
        return {"status": "failed", "reason": _redact((p.stderr or "no output").strip()[-300:])}
    if res.get("error"):
        return {"status": "failed", "reason": res["error"][:300]}
    res["status"] = "ran"
    return res

def stage_vision(findings, accounts, faces=False, deepface=False, clip=False, threshold=0.5, base=None):
    """Local face / CLIP analysis over the captured pictures (ml/vision.py in its own venv).

    Stages: hash (already done by the caller) -> InsightFace -> DeepFace confirmer -> CLIP.
    `accounts` is the exact list vision.py indexes as acct:<i>, so merge_vision must get
    the same list. Nothing leaves the machine; the models are read from ml/models."""
    if not (faces or clip):
        return {"status": "skipped", "reason": "not requested (--faces / --clip)"}
    if not ML_PY.exists():
        return {"status": "skipped", "reason": "local vision stack missing (dashboard/install-ml.sh)"}
    if faces and not (OSINT / "ml" / "models" / "models" / "buffalo_l").is_dir():
        return {"status": "skipped", "reason": "face model not downloaded yet (ml/.venv/bin/python ml/vision.py warmup)"}
    if deepface and not DEEPFACE_WEIGHTS.is_dir():
        deepface = False
        findings["deepface_note"] = "DeepFace weights missing: run ml/.venv/bin/python ml/vision.py warmup"
    doc = {"target_images": findings.get("target_images") or [], "accounts": accounts,
           "metadata": findings.get("metadata") or []}
    base_args = ["--threshold", str(threshold)] + (["--base", str(base)] if base else [])

    # TensorFlow (DeepFace) and torch (CLIP) abort the process when both load beside
    # onnxruntime, so CLIP gets its own subprocess whenever DeepFace runs.
    split = deepface and clip
    first = base_args + (["--faces"] if faces else []) + (["--deepface"] if deepface else []) \
        + ([] if split else (["--clip"] if clip else []))
    res = _vision_call(doc, first)
    if res.get("status") == "failed":
        return res
    if split:
        cres = _vision_call(doc, base_args + ["--clip"])
        if cres.get("status") == "failed":
            res["clip_error"] = cres.get("reason")
        else:
            res["clip_similar"] = cres.get("clip_similar") or []
            res.setdefault("ran", {})["clip"] = True
            res.setdefault("engine", {})["clip"] = (cres.get("engine") or {}).get("clip")
    res["flags"] = {"faces": faces, "deepface": deepface, "clip": clip}
    return res

def _add_match(ti, acc, tier, kind, score):
    """Record a vision match on a target image; an existing hash match only gains the score."""
    for m in ti.setdefault("matches", []):
        if m.get("url") == acc.get("url"):
            # several faces in one picture yield several pairs; keep the best per kind
            m[f"{kind}_score"] = max(m.get(f"{kind}_score") or 0, score)
            if MATCH_TIER_ORDER.get(tier, 9) < MATCH_TIER_ORDER.get(m.get("tier"), 9):
                m["tier"], m["kind"], m["score"] = tier, kind, score
            return
    ti["matches"].append({"site": acc.get("site") or "?", "user": acc.get("user") or "",
                          "url": acc.get("url") or "", "display_name": acc.get("display_name") or "",
                          "tier": tier, "kind": kind, "score": score,
                          "avatar": acc.get("avatar") or "", "avatar_src": acc.get("avatar_src") or ""})

def merge_vision(findings, res, accounts):
    """Fold vision.py output into target-image matches, account rows and face clusters."""
    if res.get("status") != "ran":
        return
    tis = findings.get("target_images") or []

    def _acct(key):
        kind, _, idx = key.partition(":")
        if kind in ("acct", "cover") and idx.isdigit() and int(idx) < len(accounts):
            return accounts[int(idx)]
        return None

    def _target(key):
        kind, _, idx = key.partition(":")
        if kind == "target" and idx.isdigit() and int(idx) < len(tis):
            return tis[int(idx)]
        return None

    parent = {}
    def find(k):
        while parent.setdefault(k, k) != k:
            k = parent[k]
        return k
    for m in res.get("face_matches") or []:
        for ka, kb in ((m["a"], m["b"]), (m["b"], m["a"])):
            ti, acc = _target(ka), _acct(kb)
            if ti is not None and acc is not None:
                _add_match(ti, acc, "face", "face", m["score"])
                acc["face_match"] = max(acc.get("face_match") or 0, m["score"])
                acc["target_image_match"] = acc.get("target_image_match") or "face"
        a, b = _acct(m["a"]), _acct(m["b"])
        if a is not None and b is not None and _host(a.get("url")) != _host(b.get("url")):
            parent[find(id(a))] = find(id(b))
    for m in res.get("clip_similar") or []:
        ti, acc = _target(m["a"]), _acct(m["b"])
        if ti is not None and acc is not None:
            _add_match(ti, acc, "similar", "clip", m["score"])

    # DeepFace is a confirmer: it annotates InsightFace's pairs, it never adds one.
    # Verdicts are kept per picture, not per account: acct:<i> and cover:<i> are the same row
    # but different photographs, and a refused banner must not condemn the profile picture.
    # A picture is stamped only when DeepFace vouched for it in NO pair, so a photo confirmed
    # against the reference keeps its face even if some other pairing was refused.
    seen, disputed_edges = {}, []
    for c in res.get("deepface_confirms") or []:
        st = c.get("status")
        if st == "disputed":
            disputed_edges.append(c)
        for ka, kb in ((c["a"], c["b"]), (c["b"], c["a"])):
            acc = _acct(ka)
            if acc is None:
                continue
            kind = ka.partition(":")[0]
            seen.setdefault((id(acc), kind), set()).add(st)
            if kind != "acct":
                continue        # a cover verdict says nothing about the avatar shown in a match row
            ti = _target(kb)
            if ti is not None:
                for m in ti.get("matches") or []:
                    if m.get("url") == acc.get("url"):
                        m["deepface_status"] = st
                        m["deepface_models"] = c.get("models") or []
    _fold = lambda st: ("confirmed" if "confirmed" in st
                        else "disputed" if "disputed" in st else "abstained")
    for acc in accounts:
        if seen.get((id(acc), "acct")):
            acc["deepface_status"] = _fold(seen[(id(acc), "acct")])
        if seen.get((id(acc), "cover")):
            acc["cover_deepface_status"] = _fold(seen[(id(acc), "cover")])
    # deepface_marked means the stamp really went into the pixels; the dashboard draws its own
    # banner only when it did not, so an unreadable picture is still flagged somewhere.
    # The clean copy is kept because ml/vision.py reads these fields back on the next run and
    # must never re-grade a stamped picture.
    for acc in accounts:
        if acc.get("deepface_status") == "disputed" and acc.get("avatar") and not acc.get("deepface_marked"):
            marked = _watermark(acc["avatar"])
            if marked != acc["avatar"]:
                acc["avatar_plain"] = acc["avatar"]
                acc["avatar"], acc["deepface_marked"] = marked, True
        if acc.get("cover_deepface_status") == "disputed" and acc.get("cover_thumb") and not acc.get("cover_marked"):
            marked = _watermark(acc["cover_thumb"])
            if marked != acc["cover_thumb"]:
                acc["cover_thumb_plain"] = acc["cover_thumb"]
                acc["cover_thumb"], acc["cover_marked"] = marked, True
    for ti in tis:
        for m in ti.get("matches") or []:
            if m.get("deepface_status") == "disputed" and m.get("avatar") and not m.get("deepface_marked"):
                marked = _watermark(m["avatar"])
                if marked != m["avatar"]:
                    m["avatar"], m["deepface_marked"] = marked, True

    for ti in tis:
        (ti.get("matches") or []).sort(key=lambda m: (MATCH_TIER_ORDER.get(m.get("tier"), 9), -(m.get("score") or 0)))

    by_root = {}
    for acc in accounts:
        if id(acc) in parent:
            by_root.setdefault(find(id(acc)), []).append(acc)
    groups = []
    for members in by_root.values():
        if len({_host(x.get("url")) for x in members}) < 2:
            continue
        keys = {id(x) for x in members}
        scores = [m["score"] for m in res.get("face_matches") or []
                  if id(_acct(m["a"]) or 0) in keys and id(_acct(m["b"]) or 0) in keys]
        groups.append({"members": [{"site": x.get("site"), "user": x.get("user"), "url": x.get("url"),
                                    "avatar": x.get("avatar") or ""} for x in members],
                       "min_score": min(scores) if scores else None,
                       "max_score": max(scores) if scores else None})
    groups.sort(key=lambda g: -(g["max_score"] or 0))
    for i, g in enumerate(groups, 1):
        urls = {x["url"] for x in g["members"]}
        for acc in accounts:
            if acc.get("url") in urls:
                acc["face_group"] = i
        g["deepface_disputed"] = sum(
            1 for c in disputed_edges
            if {(_acct(c["a"]) or {}).get("url"), (_acct(c["b"]) or {}).get("url")} <= urls)
    findings["face_groups"] = groups

_SCRIPT_RE = re.compile(r"<(script|style|template|noscript)\b[^>]*>.*?</\1>", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")
_TR_MAP = str.maketrans("çğıöşüÇĞİÖŞÜ", "cgiosucgiosu")

def _visible_text(doc, cap=200000):
    """The text a human would actually see, lower-cased and Turkish-folded.

    Script/style bodies and tag attributes are dropped: the handle in a canonical <link>
    or share href is circular evidence, since the tools built the URL from it."""
    s = _SCRIPT_RE.sub(" ", doc[:cap])
    # A block whose closing tag falls beyond the cap leaves an unterminated opener the
    # paired pattern cannot match; everything after it is inside that block.
    s = re.sub(r"<(?:script|style|template|noscript)\b[^>]*>.*$", " ", s, flags=re.I | re.S)
    s = _TAG_RE.sub(" ", s)
    s = html.unescape(s)
    return re.sub(r"\s+", " ", s.translate(_TR_MAP).lower())

def _handle_evidence(us, text):
    """Does this text contain the handle as its own token?

    Anchored: an unanchored substring test verifies short handles on chance alone."""
    if not us or len(us) < 4 or not text:
        return False
    if re.search(rf"(?<![a-z0-9]){re.escape(us)}(?![a-z0-9])", text):
        return True
    # Separator-tolerant match, only for handles long enough to rule out chance.
    return len(us) >= 6 and us in re.sub(r"[^a-z0-9]", "", text)

def verify_account(acc, fetch_avatar=True, timeout=15):
    out = dict(acc)
    out["via"] = sorted(acc.get("via") or [])
    url, user = acc.get("url") or "", acc.get("user") or ""
    if not url:
        out["state"] = "unknown"; return out
    try:
        import requests
        _opsec("target_hosts", _host(url))
        r = requests.get(url, timeout=timeout, allow_redirects=True, proxies=PROXIES, stream=True,
                         headers={"User-Agent": BROWSER_UA, "Accept-Language": "en-US,en;q=0.9"})
        # Why the body is empty must survive to the decision below; an unreadable page
        # must not become a positive.
        ctype = (r.headers.get("content-type") or "").lower()
        read_note = ""
        if "text" in ctype or "html" in ctype:
            blob = _read_capped(r, 4_000_000)
            if blob is None:
                doc, read_note = "", "body exceeded the 4 MB read cap"
            else:
                try:
                    doc = blob.decode(r.encoding or "utf-8", errors="replace")[:2000000]
                except (LookupError, TypeError):
                    # An unparseable charset header must not cost us the page.
                    doc = blob.decode("utf-8", errors="replace")[:2000000]
        else:
            r.close(); doc = ""
            read_note = f"non-text response ({ctype.split(';')[0].strip() or 'unknown type'})"
    except Exception as e:
        out["state"] = "error"; out["status"] = 0; out["note"] = type(e).__name__
        return out

    out["status"] = r.status_code
    out["final_url"] = str(r.url)
    m = re.search(r"<title[^>]*>([^<]{0,400})", doc, re.I)
    title = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:200] if m else ""
    ogt = _meta(doc, "og:title")
    ogd = _meta(doc, "og:description") or _meta(doc, "description")
    out["title"], out["description"] = title, ogd
    out["display_name"] = _display_name(title, ogt, user, acc.get("site") or "")

    us = _slug(user)
    vis = _visible_text(doc)
    ttl = f"{title} {ogt}".translate(_TR_MAP).lower()
    in_body = _handle_evidence(us, vis)
    in_title = _handle_evidence(us, ttl)
    blurb = f"{title} {ogd}".lower()

    if r.status_code in (404, 410):
        out["state"] = "dead"
    # BOT_MARKERS are only trustworthy on a non-200: on a 200 they would match the
    # profile's own bio.
    elif r.status_code in (401, 403, 429) or (r.status_code != 200
                                              and any(k in blurb for k in BOT_MARKERS)):
        out["state"] = "blocked"
        out["display_name"] = ""          # the challenge page's title is not a person
        out["description"] = ""
    elif r.status_code != 200:
        out["state"] = "unknown"
    # Must run BEFORE any page evidence: a consent screen echoes the destination URL,
    # handle included, inside its own markup.
    elif any(k in title.lower() for k in INTERSTITIAL_TITLES):
        out["state"] = "unconfirmed"
        out["note"] = "interstitial page (consent / bot check), not the profile itself"
        out["display_name"] = ""
        out["description"] = ""
    # DEAD_MARKERS match the <title> only: a bio reading "404: bio not found" is a common joke.
    elif any(k in title.lower() for k in DEAD_MARKERS):
        out["state"] = "dead"
    elif in_body:
        out["state"] = "verified"
    elif in_title:
        # Handle in the page's own title ("Contact @user"): weaker than body text but
        # still the page talking about this account.
        out["state"] = "verified"
    else:
        # The handle in the URL is not evidence (the tools built the URL from it);
        # undecided, and the archive.org check runs next.
        out["state"] = "unconfirmed"
        if read_note:
            out["note"] = read_note
        elif not doc:
            out["note"] = "empty response body"

    if fetch_avatar and out["state"] == "verified":
        cands = _avatar_candidates(doc, url=out.get("final_url") or url, site=acc.get("site") or "", user=user)
        thumb_res = _thumb(cands)
        out["avatar"], out["avatar_hash"], out["avatar_src"], out["avatar_sha256"] = thumb_res
        out["avatar_hashes"] = getattr(thumb_res, "hashes", {})
        out["avatar_is_generated"] = getattr(thumb_res, "is_generated", False)
        hd_file = _save_image(out.get("avatar_sha256"), getattr(thumb_res, "hd", b""))
        if hd_file:
            out["avatar_file"] = hd_file
        cover = getattr(thumb_res, "cover", {})
        if cover.get("url"):
            out["cover_url"] = cover["url"]
            out["cover_thumb"] = cover.get("data_uri", "")
    if out["state"] == "dead":
        # A 404's title is the site's error page, not a person.
        out["display_name"] = ""
        out["description"] = ""
    out["emails"] = sorted(set(EMAIL_RE.findall(f"{title} {ogd}")))
    return out

# Two labels are not always the registrable domain: under these, foo.co.uk and bar.co.uk
# are different sites, and collapsing them made the cross-platform photo gate reject real
# evidence and the OPSEC ledger undercount hosts.
_CC_SLD = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.tr", "net.tr", "org.tr", "edu.tr", "gov.tr", "k12.tr",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.nz", "net.nz", "org.nz", "com.br", "net.br", "org.br",
    "co.za", "org.za", "com.mx", "com.ar", "com.co", "com.pe",
    "co.in", "net.in", "org.in", "com.cn", "net.cn", "org.cn",
    "co.kr", "or.kr", "com.sg", "com.hk", "com.tw", "com.my",
    "com.ph", "com.vn", "co.th", "co.id", "com.pk", "com.bd",
    "co.il", "com.sa", "com.eg", "com.ng", "com.ua", "com.pl",
    "com.ru", "com.es", "com.pt", "com.gr", "com.cy",
}

def _host(url):
    m = re.match(r"https?://([^/]+)", url or "")
    if not m:
        return ""
    parts = re.sub(r"^www\.", "", m.group(1).lower()).split(".")
    if len(parts) < 2:
        return parts[0]
    if len(parts) >= 3 and ".".join(parts[-2:]) in _CC_SLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def stage_wayback(url, timeout=30):
    """Ask the Internet Archive whether this profile URL was ever captured.

    Costs nothing in OPSEC terms (the target site is never touched). Asymmetric: a snapshot
    proves existence, absence proves nothing, so it can only upgrade a verdict."""
    u = re.sub(r"^https?://", "", url or "").rstrip("/")
    if not u:
        return {}
    try:
        import requests
        _opsec("third_parties", "web.archive.org")
        r = requests.get("https://web.archive.org/cdx/search/cdx", proxies=PROXIES,
                         params={"url": u, "output": "json", "limit": 20,
                                 "fl": "timestamp,statuscode", "collapse": "timestamp:6"},
                         headers={"User-Agent": BROWSER_UA}, timeout=(10, timeout))
        if r.status_code == 403:
            return {"note": "archive.org will not answer for this domain (site exclusion)"}
        if r.status_code != 200:
            return {"note": f"archive.org HTTP {r.status_code}"}
        rows = r.json()[1:]
    except Exception as e:
        return {"note": f"{type(e).__name__}"}
    if not rows:
        return {"snapshots": 0, "note": "never archived — this says nothing either way"}
    good = [x for x in rows if str(x[1]).startswith("2")]
    out = {"snapshots": len(rows), "ok_snapshots": len(good),
           "first": rows[0][0][:8], "last": rows[-1][0][:8]}
    if good:
        out["existed"] = True
        out["wayback_url"] = f"https://web.archive.org/web/{good[-1][0]}/{url}"
    return out

def settle_unresolved(accounts, workers=6):
    """Run the archive check over exactly the accounts we could not decide ourselves."""
    todo = [a for a in accounts if a.get("state") in ("unconfirmed", "unknown", "blocked", "error")]
    if not todo:
        return 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for acc, res in zip(todo, ex.map(lambda a: stage_wayback(a.get("url")), todo)):
            acc["archive"] = res
    return sum(1 for a in todo if (a.get("archive") or {}).get("existed"))

def _images_match(a, b, max_dhash=6, max_phash=8):
    """Check if two accounts share the same photo, accounting for cropping differences.
    Returns (matched: bool, tier: str)."""
    # 1. Byte-identical sha256 is strong evidence
    if a.get("avatar_sha256") and a["avatar_sha256"] == b.get("avatar_sha256"):
        return True, "strong"

    # 2. dHash comparison (full & center crop)
    dh_a = [h for h in (a.get("avatar_hashes", {}).get("dhash"),
                        a.get("avatar_hashes", {}).get("dhash_center")) if h is not None]
    if not dh_a and a.get("avatar_hash"):
        try:
            dh_a = [int(a["avatar_hash"], 16)]
        except ValueError:
            pass

    dh_b = [h for h in (b.get("avatar_hashes", {}).get("dhash"),
                        b.get("avatar_hashes", {}).get("dhash_center")) if h is not None]
    if not dh_b and b.get("avatar_hash"):
        try:
            dh_b = [int(b["avatar_hash"], 16)]
        except ValueError:
            pass

    if dh_a and dh_b:
        min_dh = min(bin(h1 ^ h2).count("1") for h1 in dh_a for h2 in dh_b)
        if min_dh <= max_dhash:
            return True, "possible"

    # 3. pHash comparison (full & center crop)
    ph_a = [h for h in (a.get("avatar_hashes", {}).get("phash"),
                        a.get("avatar_hashes", {}).get("phash_center")) if h is not None]
    ph_b = [h for h in (b.get("avatar_hashes", {}).get("phash"),
                        b.get("avatar_hashes", {}).get("phash_center")) if h is not None]
    if ph_a and ph_b:
        min_ph = min(bin(h1 ^ h2).count("1") for h1 in ph_a for h2 in ph_b)
        if min_ph <= max_phash:
            return True, "possible"

    return False, ""

def group_by_photo(accounts, max_dist=6):
    """Accounts sharing the same profile picture, at two evidence tiers.

    Byte-identical (sha256) is strong; a perceptual match (dHash <= 6 or pHash <= 8,
    full or center-cropped) is possible.
    Near-flat hashes and generated letter-avatars are dropped from grouping."""
    usable = []
    for a in accounts:
        if not a.get("avatar_hash"):
            continue
        if a.get("avatar_is_generated"):
            a["photo_note"] = "generated/letter avatar — excluded from cross-platform grouping"
            continue
        try:
            bits = bin(int(a["avatar_hash"], 16)).count("1")
        except ValueError:
            continue
        if bits < 8 or bits > 56:
            a["photo_note"] = "default/near-flat avatar — too generic to be evidence"
            continue
        usable.append(a)

    # Compare against every member, not just the first, so membership does not depend on input order.
    groups = []
    for a in usable:
        for g in groups:
            if any(_images_match(a, m, max_dhash=max_dist, max_phash=8)[0]
                   for m in g["members"]):
                g["members"].append(a)
                break
        else:
            groups.append({"members": [a]})

    out = []
    for g in groups:
        hosts = {_host(m.get("url")) for m in g["members"]} - {""}
        if len(g["members"]) < 2 or len(hosts) < 2:
            continue
        by_sha = {}
        for m in g["members"]:
            if m.get("avatar_sha256"):
                by_sha.setdefault(m["avatar_sha256"], set()).add(_host(m.get("url")))
        g["tier"] = "strong" if any(len(v) > 1 for v in by_sha.values()) else "possible"
        g["hosts"] = sorted(hosts)
        out.append(g)
    for i, g in enumerate(out, 1):
        for m in g["members"]:
            m["photo_group"] = i
            m["photo_tier"] = g["tier"]
    return out

def stage_verify(accounts, workers=8, fetch_avatar=True):
    items = list(accounts)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        return list(ex.map(lambda a: verify_account(a, fetch_avatar=fetch_avatar), items))

# ---------------- helper: pull new identifiers out of findings ----------------
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
HANDLE_RE = re.compile(r"^[A-Za-z0-9._\-]{3,40}$")
def harvest_new_identifiers(findings, known_users, known_emails, wide=False):
    """Identifiers worth following, taken from ATTRIBUTABLE fields only.

    Every address in the blob (whois, bios) would mean investigating strangers on the
    subject's say-so. Provenance goes to findings["correlation_sources"]; wide=True follows any."""
    new_users, new_emails = set(), set()
    prov = findings.setdefault("correlation_sources", {})
    lower_e = {x.lower() for x in known_emails}
    lower_u = {x.lower() for x in known_users}

    def add_email(e, source):
        e = (e or "").strip().strip(".,;:<>()[]\"'")
        if e and e.lower() not in lower_e and EMAIL_RE.fullmatch(e):
            new_emails.add(e)
            prov.setdefault(e, source)

    # Gravatar hands back confirmed cross-platform handles, worth re-running sherlock/maigret on.
    for r in (findings.get("email") or {}).values():
        for a in ((r.get("gravatar") or {}).get("accounts") or []):
            u = (a.get("username") or "").strip()
            if u and u.lower() not in lower_u and HANDLE_RE.match(u):
                new_users.add(u)

    for row in (findings.get("verified") or []):
        if row.get("state") == "verified":
            for e in (row.get("emails") or []):
                add_email(e, f"published on the {row.get('site') or _host(row.get('url'))} profile")

    for d, r in (findings.get("domain") or {}).items():
        dom = (d or "").lower().lstrip(".")
        if not dom:
            continue
        def in_domain(addr):
            a_ = (addr or "").lower()
            return a_.endswith("@" + dom) or a_.endswith("." + dom)
        for e in ((r.get("theHarvester") or {}).get("emails") or []):
            if in_domain(e):
                add_email(e, f"theHarvester on {d}")
        for x in ((r.get("hunter") or {}).get("emails") or []):
            e = (x or {}).get("value") or ""
            if in_domain(e):
                add_email(e, f"hunter.io on {d}")

    if wide:
        for e in EMAIL_RE.findall(json.dumps(findings, ensure_ascii=False)):
            add_email(e, "free-text scan (--follow-any-email)")
    return new_users, new_emails

# ---------------- main ----------------
def main():
    ap = argparse.ArgumentParser(prog="kargu", description="KARGU-OSINT orchestrator")
    ap.add_argument("target", help="path to the target profile .txt")
    ap.add_argument("--deep", action="store_true", help="SpiderFoot deep scan (slow)")
    ap.add_argument("--tor", action="store_true", help="route tools through proxychains/Tor")
    ap.add_argument("--depth", type=int, default=1, help="correlation loop depth (default 1)")
    ap.add_argument("--max-users", type=int, default=3, help="max candidate usernames derived from name/e-mail")
    ap.add_argument("--no-derive", action="store_true", help="do not derive candidate usernames")
    ap.add_argument("--follow-any-email", action="store_true",
                    help="correlation: follow every address found anywhere in the results, including "
                         "profile bios and whois text (off by default — it pulls in third parties)")
    ap.add_argument("--no-api", action="store_true", help="skip API-key sources (numverify/VT/Chaos/Hunter/HIBP)")
    ap.add_argument("--no-verify", action="store_true", help="do not open the found account URLs to verify/enrich them")
    ap.add_argument("--no-avatars", action="store_true", help="verify accounts but do not embed profile pictures")
    ap.add_argument("--verify-workers", type=int, default=8, help="parallel requests used while verifying accounts")
    ap.add_argument("--no-instagram", action="store_true", help="skip the Instagram profile lookup (instaloader)")
    ap.add_argument("-i", "--image", action="append", default=[],
                    help="target reference image path or URL for visual matching & reverse search")
    ap.add_argument("--faces", action="store_true",
                    help="compare faces across the captured pictures with the local InsightFace model "
                         "(biometric processing: opt-in, needs dashboard/install-ml.sh)")
    ap.add_argument("--deepface", action="store_true",
                    help="re-check every InsightFace match with DeepFace (Facenet512 + VGG-Face); a match "
                         "DeepFace refuses is marked disputed and its picture is stamped")
    ap.add_argument("--clip", action="store_true",
                    help="CLIP visual similarity between reference images and captured pictures (local)")
    ap.add_argument("--face-threshold", type=float, default=0.5,
                    help="cosine similarity a face pair must reach to count as a match (default 0.5)")
    ap.add_argument("--no-lockdown", action="store_true",
                    help="do not enable Mullvad lockdown mode for the duration of the scan")
    args = ap.parse_args()
    use_api = not args.no_api

    tpath = pathlib.Path(args.target).expanduser().resolve()
    if not tpath.exists():
        print(f"ERROR: target file not found: {tpath}"); sys.exit(2)

    if args.tor:
        good, msg = enable_tor()
        if not good:
            print(_c("1;31", f"ERROR: --tor was requested but {msg}"))
            print(_c("33", "Refusing to run: a scan that looks anonymous but is not is worse "
                           "than no Tor at all. Drop --tor to scan normally."))
            sys.exit(3)
        print(_c("32", f"[TOR] {msg}"))

    eg = egress_info(via_tor=args.tor)
    OPSEC_LOG["egress"] = eg
    if eg.get("error"):
        warn(f"could not determine the exit address ({eg['error']})")
    elif eg.get("tor"):
        print(_c("32", f"[EXIT] Tor · {eg.get('ip')} ({eg.get('country')})"))
    elif eg.get("mullvad"):
        print(_c("32", f"[EXIT] Mullvad VPN · {eg.get('ip')} ({eg.get('country')})"))
    else:
        print(_c("1;33", f"[EXIT] direct · {eg.get('ip')} ({eg.get('org')}, {eg.get('country')})"))
        if shutil.which("mullvad"):
            rc_, out_, _e_ = run([shutil.which("mullvad"), "status"], timeout=15)
            if "Disconnected" in out_:
                print(_c("1;33", "        Mullvad is installed but disconnected — this scan is "
                                 "attributable to your own connection. `mullvad connect` first, "
                                 "or use --tor."))

    # Lockdown is scan-scoped: enabled here, restored to its previous value on any exit.
    if shutil.which("mullvad") and eg.get("mullvad"):
        prev = _mullvad_lockdown_get()
        OPSEC_LOG["lockdown"] = prev
        if prev == "off" and not args.no_lockdown:
            if _mullvad_lockdown_set("on"):
                OPSEC_LOG["lockdown"] = "on (for this scan)"
                _RESTORE.append(lambda: _mullvad_lockdown_set("off"))
                print(_c("32", "[LOCK] Mullvad lockdown enabled for this scan; restored on exit"))
        elif prev == "off":
            print(_c("1;33", "        Mullvad lockdown is OFF: if the VPN drops mid-scan, traffic continues over your ISP."))

    prof = parse_target(tpath)
    global IMAGES_DIR
    IMAGES_DIR = tpath.parent / "images"
    for img in args.image:
        if img and img not in prof.get("image", []):
            prof.setdefault("image", []).append(img)
    prof["_derived"] = []
    prof["_derived_emails"] = []     # addresses the scan discovered, kept apart from the input
    prof["_depth_used"] = args.depth
    if not args.no_derive:
        derived = derive_usernames(prof, cap=args.max_users)
        if derived:
            print(f"[DERIVE] {len(derived)} candidate username(s) from name/e-mail: {', '.join(derived)}")
            prof["_derived"] = derived
            prof["username"] = prof["username"] + derived

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    active = [n for n, v in (("numverify", key("NUMVERIFY_API_KEY")), ("virustotal", key("VIRUSTOTAL_API_KEY")),
                             ("chaos", key("CHAOS_API_KEY")), ("hunter.io", key("HUNTER_API_KEY")),
                             ("hibp", key("HIBP_API_KEY"))) if v]
    head(f"=== KARGU-OSINT scan started: {tpath.name} @ {ts} ===")
    print(f"Input -> username:{len(prof['username'])} email:{len(prof['email'])} "
          f"phone:{len(prof['phone'])} domain:{len(prof['domain'])} file:{len(prof['file'])} "
          f"image:{len(prof.get('image', []))} "
          f"{'[TOR]' if args.tor else ''}")
    print(f"API keys active: {', '.join(active) if (active and use_api) else 'none'}\n")

    findings = {"target_file": str(tpath), "timestamp": ts, "input": prof, "api_keys_active": active if use_api else [],
                "identity": {}, "email": {}, "domain": {}, "phone": [], "metadata": [], "deep": None,
                "target_images": []}

    target_images = []
    all_img_sources = list(prof.get("image", []))
    img_exts = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}
    for f in prof.get("file", []):
        if pathlib.Path(f).suffix.lower() in img_exts and f not in all_img_sources:
            all_img_sources.append(f)
    for img_src in all_img_sources:
        step(f"[VISUAL] loading target reference image: {img_src}")
        ti = process_target_image(img_src)
        if ti.get("error"):
            warn(f"target image ({img_src}): {ti['error']}")
        else:
            ok(f"target image ready ({ti.get('dimensions', '?')}, sha256:{ti.get('sha256', '')[:12]}…)")
        target_images.append(ti)
    findings["target_images"] = target_images

    seen_users = set(u.lower() for u in prof["username"])
    seen_emails = set(e.lower() for e in prof["email"])

    def process_users(users):
        for u in users:
            step(f"[IDENTITY] username: {u}")
            r = {}
            log("sherlock ..."); r["sherlock"] = stage_sherlock(u)
            if r["sherlock"].get("failed"): warn(f"sherlock: {r['sherlock']['failed']}")
            else: ok(f"{len(r['sherlock'].get('hits',[]))} account(s)")
            log("maigret ...");  r["maigret"] = stage_maigret(u)
            if r["maigret"].get("failed"): warn(f"maigret: {r['maigret']['failed']}")
            else: ok(f"{len(r['maigret'].get('hits',[]))} account(s)")
            findings["identity"][u] = r

    def process_emails(emails):
        for e in emails:
            step(f"[E-MAIL] {e}")
            r = {}
            log("holehe ...");   r["holehe"] = stage_holehe(e)
            if r["holehe"].get("failed"): warn(f"holehe: {r['holehe']['failed']}")
            else: ok(f"{len(r['holehe'].get('used',[]))} site(s) registered")
            log("h8mail ...");   r["h8mail"] = stage_h8mail(e)
            if r["h8mail"].get("failed"): warn(f"h8mail: {r['h8mail']['failed']}")
            log("gravatar ..."); r["gravatar"] = stage_gravatar(e)
            if r["gravatar"].get("found"):
                ok(f"gravatar profile: {r['gravatar'].get('display_name') or r['gravatar'].get('profile_url')}")
            if use_api:
                r["hibp"] = stage_hibp(e)
                if r["hibp"].get("breaches"):
                    ok(f"HIBP: {len(r['hibp']['breaches'])} breach(es)")
                r["hunter"] = stage_hunter_verify(e)
            findings["email"][e] = r

    process_users(prof["username"])
    process_emails(prof["email"])

    q = prof["username"] + prof["email"]
    if q:
        step("[SOCIAL] socialscan (availability / registration)")
        findings["socialscan"] = stage_socialscan(q)
        ss = findings["socialscan"]
        if ss.get("failed"):   warn(f"socialscan: {ss['failed']}")
        elif ss.get("skipped"): warn(f"socialscan: {ss['skipped']}")
        else: ok(f"{sum(1 for r in ss['results'] if r.get('taken'))} taken "
                 f"of {len(ss['results'])} platform check(s)")

    def correlate():
        """Re-run the per-identifier stages on whatever the scan has just discovered.

        Must be called AFTER verification and the domain stage, the richest producers
        of new addresses."""
        for _ in range(max(0, args.depth)):
            nu, ne = harvest_new_identifiers(findings, seen_users, seen_emails,
                                             wide=args.follow_any_email)
            ne = [e for e in ne if e.lower() not in seen_emails]
            nu = [u for u in nu if u.lower() not in seen_users]
            if not ne and not nu:
                break
            if nu:
                step(f"[CORRELATION] {len(nu)} new username(s) discovered: {', '.join(nu)}")
                for u in nu: seen_users.add(u.lower())
                process_users(nu)
                prof["username"] += nu
            if ne:
                step(f"[CORRELATION] {len(ne)} new e-mail(s) discovered, processing ...")
                src = findings.get("correlation_sources") or {}
                for e in ne:
                    log(f"  {e}  <- {src.get(e, 'unknown source')}")
                for e in ne: seen_emails.add(e.lower())
                process_emails(ne)
                prof["email"] += ne
                # Keep discovered addresses distinguishable from operator input in the report.
                prof["_derived_emails"] += list(ne)

    if not args.no_verify:
        raw_accounts = [dict(x, via=sorted(x["via"])) for x in _identity_summary(findings).values()]
        if raw_accounts:
            step(f"[VERIFY] opening {len(raw_accounts)} account URL(s) — real or false positive, and what do they show?")
            findings["verified"] = stage_verify(raw_accounts, workers=args.verify_workers,
                                                fetch_avatar=not args.no_avatars)
            findings["did_verify"] = True
            counts = {}
            for v in findings["verified"]:
                counts[v.get("state", "unknown")] = counts.get(v.get("state", "unknown"), 0) + 1
            ok(" · ".join(f"{STATE_LABEL.get(k, k)}: {n}" for k, n in
                          sorted(counts.items(), key=lambda kv: STATE_ORDER.get(kv[0], 9))))
            ver_accs = [v for v in findings["verified"] if v.get("state") == "verified"]
            n_ver = len(ver_accs)
            n_av = sum(1 for v in ver_accs if v.get("avatar"))
            pct = round((n_av / n_ver) * 100) if n_ver else 0
            ok(f"avatar capture rate: {n_av}/{n_ver} verified accounts ({pct}%)")
            names = sorted({v["display_name"] for v in findings["verified"]
                            if v.get("state") == "verified" and v.get("display_name")})
            if names:
                ok("real name candidates: " + ", ".join(names[:6]))
            for i, g in enumerate(group_by_photo(findings["verified"]), 1):
                ok(f"same profile photo #{i} [{g.get('tier', 'possible')}] on "
                   f"{len(g['members'])} sites: "
                   + ", ".join(m.get("site") or "?" for m in g["members"]))

            unresolved = [a for a in findings["verified"]
                          if a.get("state") in ("unconfirmed", "unknown", "blocked", "error")]
            if unresolved:
                log(f"archive check on {len(unresolved)} undecided account(s) "
                    f"(asks archive.org, never the target's site) ...")
                n = settle_unresolved(findings["verified"], workers=args.verify_workers)
                ok(f"{n} of them were archived at least once — those profiles really existed")

    if not args.no_instagram and prof["username"]:
        step(f"[INSTAGRAM] looking up {len(prof['username'])} handle(s) via instaloader")
        res = enrich_instagram(findings, prof["username"], use_tor=args.tor,
                               fetch_avatar=not args.no_avatars)
        for u, r in res.items():
            if r.get("ok"):
                ok(f"@{u}: {r.get('full_name') or '—'} · {r.get('followers')} followers"
                   + (" · private" if r.get("is_private") else "")
                   + (f" · business ({r.get('business_category')})" if r.get("is_business") else "")
                   + (" · avatar captured" if r.get("avatar") else ""))
            else:
                warn(f"@{u}: {r.get('skipped')}")
        if any(r.get("ok") for r in res.values()):
            for i, g in enumerate(group_by_photo(findings["verified"]), 1):
                ok(f"same profile photo #{i} [{g.get('tier', 'possible')}] (with Instagram): "
                   + ", ".join(m.get("site") or "?" for m in g["members"]))

    for d in prof["domain"]:
        step(f"[DOMAIN] {d}")
        r = {}
        log("theHarvester ..."); r["theHarvester"] = stage_theharvester(d, use_api=use_api)
        if r["theHarvester"].get("failed"): warn(f"theHarvester: {r['theHarvester']['failed']}")
        else: ok(f"{len(r['theHarvester'].get('emails',[]))} email / {len(r['theHarvester'].get('hosts',[]))} host")
        log("crt.sh ...");       r["crtsh"] = stage_crtsh(d)
        if r["crtsh"].get("skipped"):
            warn(f"certificates: {r['crtsh']['skipped']}")
        else:
            ok(f"{len(r['crtsh'].get('subdomains',[]))} subdomain(s) via "
               f"{r['crtsh'].get('tool', 'crt.sh')}")
        if use_api:
            log("virustotal ..."); r["virustotal"] = stage_virustotal(d)
            if r["virustotal"].get("skipped"): warn(f"virustotal: {r['virustotal']['skipped']}")
            else: ok(f"reputation {r['virustotal'].get('reputation')} · {len(r['virustotal'].get('subdomains',[]))} subdomain(s)")
            log("chaos ...");      r["chaos"] = stage_chaos(d)
            if r["chaos"].get("skipped"): warn(f"chaos: {r['chaos']['skipped']}")
            else: ok(f"{len(r['chaos'].get('subdomains',[]))} subdomain(s)")
            log("hunter.io ...");  r["hunter"] = stage_hunter_domain(d)
            if r["hunter"].get("skipped"): warn(f"hunter.io: {r['hunter']['skipped']}")
            else: ok(f"{len(r['hunter'].get('emails',[]))} corporate e-mail(s)")
        log("dnstwist ...");    r["dnstwist"] = stage_dnstwist(d)
        ok(f"{len(r['dnstwist'].get('registered',[]))} look-alike domain(s)")
        findings["domain"][d] = r

    correlate()

    for ph in prof["phone"]:
        step(f"[PHONE] {ph}")
        r = stage_phone(ph, use_api=use_api)
        nv = r.get("numverify", {})
        if nv.get("skipped"): warn(f"numverify: {nv['skipped']}")
        else: ok(f"{nv.get('country_name','?')} · {nv.get('carrier') or 'carrier unknown'} · {nv.get('line_type','?')}")
        pif = r.get("phoneinfoga", {})
        if pif.get("failed"): warn(f"phoneinfoga: {pif['failed']}")
        else: ok(f"footprint dorks: {sum(pif.get('dork_counts',{}).values())}")
        findings["phone"].append(r)

    for f in prof["file"]:
        step(f"[METADATA] {f}")
        res = stage_metadata(f)
        findings["metadata"].append(res)
        if res.get("meta"):
            sm = res["meta"].get("_summary", {})
            parts = []
            if sm.get("Device"): parts.append(f"Camera: {sm['Device']}")
            if sm.get("Software"): parts.append(f"Software: {sm['Software']}")
            if sm.get("DateTime"): parts.append(f"Date: {sm['DateTime']}")
            if sm.get("Creator"): parts.append(f"Creator: {sm['Creator']}")
            if sm.get("GPS"): parts.append(f"GPS: {sm['GPS']}")
            if res["meta"].get("_thumbnail"): parts.append("Thumbnail: extracted")
            if parts:
                ok(" · ".join(parts))

    if args.deep:
        sf = tool("sf") or tool("sf.py") or shutil.which("sf")
        seed = (prof["email"] or prof["domain"] or prof["username"] or [None])[0]
        if sf and seed:
            step(f"[DEEP] SpiderFoot: {seed} (may be slow)")
            rc, out, err = run([sf, "-s", seed, "-q"], timeout=1200, use_tor=args.tor)
            fail = _fail(rc, err or out, out.strip())
            findings["deep"] = {"seed": seed, "rc": rc, "failed": fail, "out_tail": out[-4000:]}
            if fail:
                # run() captures stderr; surface it or the flag looks successful.
                warn(f"SpiderFoot did not run: {fail}")
            else:
                ok(f"{len(out.splitlines())} line(s) of SpiderFoot output")
        else:
            findings["deep"] = {"skipped": "SpiderFoot missing or no seed"}
            warn("SpiderFoot: " + findings["deep"]["skipped"])

    # Measured again at the END: only comparing the two readings shows whether the
    # advertised exit held for the whole scan.
    eg_end = egress_info(via_tor=args.tor)
    OPSEC_LOG["egress_end"] = eg_end
    changed = (not eg.get("error") and not eg_end.get("error")
               and (eg.get("ip") != eg_end.get("ip")
                    or bool(eg.get("mullvad")) != bool(eg_end.get("mullvad"))))
    OPSEC_LOG["egress_changed"] = changed
    if changed:
        _lbl = lambda e: "Mullvad" if e.get("mullvad") else "Tor" if e.get("tor") else "direct"
        print(_c("1;31", f"[EXIT] WARNING: the exit changed during the scan — started as "
                         f"{eg.get('ip')} ({_lbl(eg)}), ended as {eg_end.get('ip')} ({_lbl(eg_end)}). "
                         "Part of this scan may be attributable to your own connection."))
    elif eg_end.get("error"):
        warn(f"could not re-check the exit address at the end ({eg_end['error']})")
    OPSEC_LOG["tor"] = USE_TOR
    # Derive from what actually reported back, not from which inputs were supplied.
    tools = set()
    for r in findings["identity"].values():
        for t in ("sherlock", "maigret"):
            if not (r.get(t) or {}).get("skipped"): tools.add(t)
    for r in findings["email"].values():
        for t in ("holehe", "h8mail"):
            if not (r.get(t) or {}).get("skipped"): tools.add(t)
    for r in findings["domain"].values():
        for t, n in (("theHarvester", "theHarvester"), ("dnstwist", "dnstwist")):
            if not (r.get(t) or {}).get("skipped"): tools.add(n)
    for p in findings.get("phone", []):
        if not (p.get("phoneinfoga") or {}).get("skipped"): tools.add("phoneinfoga")
    if not (findings.get("socialscan") or {}).get("skipped") and findings.get("socialscan"):
        tools.add("socialscan")
    if any(v.get("ok") for v in (findings.get("instagram") or {}).values()):
        tools.add("instaloader")
    if findings.get("deep") and not findings["deep"].get("skipped") and not findings["deep"].get("failed"):
        tools.add("spiderfoot")
    OPSEC_LOG["tools"] = sorted(tools)
    findings["opsec"] = {k: (dict(v) if isinstance(v, dict) else v) for k, v in OPSEC_LOG.items()}

    # ---------------- VISUAL INTELLIGENCE MATCHING & SUMMARY ----------------
    target_imgs = [ti for ti in (findings.get("target_images") or []) if not ti.get("error")]
    ver_accs = [v for v in (findings.get("verified") or []) if v.get("state") == "verified"]
    if target_imgs and ver_accs:
        match_target_images_against_accounts(target_imgs, ver_accs)
    if args.faces or args.clip:
        stages = ["InsightFace"] * bool(args.faces) + ["DeepFace"] * bool(args.deepface) + ["CLIP"] * bool(args.clip)
        step(f"[VISUAL] local vision stage ({' -> '.join(stages)}) ...")
    vis = stage_vision(findings, ver_accs, faces=args.faces or args.deepface, deepface=args.deepface,
                       clip=args.clip, threshold=args.face_threshold, base=tpath.parent)
    findings["vision"] = vis
    merge_vision(findings, vis, ver_accs)

    head("=== VISUAL RESULTS ===")
    print(_c("1;36", "─── 1. OPERATOR REFERENCE IMAGES ───"))
    if findings.get("target_images"):
        for ti in findings["target_images"]:
            if ti.get("error"):
                warn(f"{ti.get('filename')}: {ti['error']}")
                continue
            matches = ti.get("matches", [])
            if matches:
                ok(f"{ti.get('filename')}: matched {len(matches)} account(s) — "
                   + ", ".join(f"{m['site']} ({m['tier']}" + (f" {m['score']:.2f}" if m.get("score") else "") + ")"
                               for m in matches))
            else:
                log(f"  {ti.get('filename')}: no profile picture match among the scanned accounts")
    else:
        log("  no reference image given (image: /path/to/photo.jpg in the target file, or -i)")

    print(_c("1;36", "─── 2. AUTO-DISCOVERED VISUAL CLUSTERS ───"))
    pgs = group_by_photo(findings.get("verified") or [])
    if pgs:
        for i, g in enumerate(pgs, 1):
            ok(f"same profile photo #{i} [{g.get('tier', 'possible')}] on {len(g['members'])} sites: "
               + ", ".join(m.get("site") or "?" for m in g["members"]))
    else:
        log("  no shared profile picture among the scanned accounts")

    print(_c("1;36", "─── 3. LOCAL VISION (hash -> InsightFace -> DeepFace -> CLIP) ───"))
    if vis.get("status") == "ran":
        ran = vis.get("ran") or {}
        if ran.get("faces"):
            ok(f"InsightFace: {vis.get('faces_total', 0)} face(s) in {len(vis.get('images') or [])} picture(s), "
               f"{len(vis.get('face_matches') or [])} cross-account pair(s) >= {vis.get('threshold')}")
            for i, g in enumerate(findings.get("face_groups") or [], 1):
                ok(f"same face #{i} (cosine {g['min_score']:.2f}-{g['max_score']:.2f}): "
                   + ", ".join(m.get("site") or "?" for m in g["members"]))
        if ran.get("deepface"):
            conf = vis.get("deepface_confirms") or []
            tally = {k: sum(1 for c in conf if c.get("status") == k) for k in ("confirmed", "disputed", "abstained")}
            ok(f"DeepFace (confirmer): {tally['confirmed']} confirmed, {tally['disputed']} disputed, "
               f"{tally['abstained']} could not be judged")
            for c in conf:
                if c.get("status") != "disputed":
                    continue
                which = ", ".join(f"{r['model']} says no ({r['distance']} > {r['threshold']})"
                                  for r in c.get("models") or [] if not r.get("verified"))
                warn(f"disputed: {c.get('a_label')} <-> {c.get('b_label')} "
                     f"(InsightFace {c.get('insightface_score')}) — {which}; picture stamped")
        elif vis.get("deepface_error"):
            warn(f"DeepFace: {vis['deepface_error']}")
        if ran.get("clip"):
            ok(f"CLIP: {len(vis.get('clip_similar') or [])} reference/captured pair(s) look alike")
    else:
        log(f"  {vis.get('status')}: {vis.get('reason')}")
    if findings.get("deepface_note"):
        warn(findings["deepface_note"])
    print()

    update_target(tpath, findings, ts)
    hpath = write_html_report(findings, tpath, ts)
    jpath = write_json_export(findings, tpath, ts)

    head("=== DONE ===")
    print(f"Folder : {tpath.parent}")
    print(f"Profile: {tpath.name}   (findings appended at the end)")
    print(f"Report : {hpath.name}")
    print(f"Data   : {jpath.name}   (machine-readable, feeds the dashboard)")
    print(_c("1;32", f"\nOpen it:  xdg-open {hpath}"))

# ---------------- JSON export ----------------
def _geo_points(findings):
    """Everything with a coordinate or a country, for the map panel."""
    pts = []
    for m in findings.get("metadata") or []:
        sm = (m.get("meta") or {}).get("_summary") or {}
        lat, lon = sm.get("GPSLatitude"), sm.get("GPSLongitude")
        if lat is not None and lon is not None:
            try:
                pts.append({"kind": "exif", "lat": float(lat), "lon": float(lon),
                            "label": os.path.basename(m.get("file") or ""),
                            "when": sm.get("DateTime") or "", "source": "exiftool"})
            except (TypeError, ValueError):
                pass
    for p in findings.get("phone") or []:
        nv = p.get("numverify") or {}
        if nv.get("country_code"):
            pts.append({"kind": "phone", "country": nv["country_code"],
                        "label": p.get("number") or "", "detail": nv.get("location") or "",
                        "source": "numverify"})
    eg = (findings.get("opsec") or {}).get("egress") or {}
    if eg.get("ip"):
        pts.append({"kind": "egress", "country": eg.get("country") or "", "city": eg.get("city") or "",
                    "label": eg.get("ip"), "source": "am.i.mullvad.net"})
    for e, r in (findings.get("email") or {}).items():
        gv = r.get("gravatar") or {}
        if gv.get("location"):
            pts.append({"kind": "gravatar", "label": e, "detail": gv["location"], "source": "gravatar"})
    return pts

def _seeds(findings):
    """Search keys the other panels pivot on."""
    inp = findings.get("input") or {}
    names = sorted({v.get("display_name") for v in findings.get("verified") or []
                    if v.get("state") == "verified" and v.get("display_name")})
    return {"names": list(dict.fromkeys(list(inp.get("name") or []) + names)),
            "usernames": list(inp.get("username") or []),
            "emails": list(dict.fromkeys(list(inp.get("email") or []) + list(inp.get("_derived_emails") or []))),
            "phones": list(inp.get("phone") or []),
            "domains": list(inp.get("domain") or [])}

def write_json_export(findings, tpath, ts):
    """<case>.json next to the .txt/.html: the same findings dict, plus derived sections
    the dashboard reads directly (geo points, pivot seeds, per-account states)."""
    doc = dict(findings)
    doc["schema"] = "kargu-case/1"
    doc["generated"] = ts
    doc["stats"] = _stats(findings)
    doc["geo"] = _geo_points(findings)
    doc["seeds"] = _seeds(findings)
    doc["accounts"] = _accounts(findings)
    J = tpath.with_suffix(".json")
    J.write_text(json.dumps(doc, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    return J

# ---------------- summaries ----------------
def _acct_key(url, site=""):
    """Identity of an account, stable across the spelling differences the two tools use.

    Keying on the raw URL would split github.com/user, github.com/User and a trailing
    slash into three accounts and fetch the page twice during verification."""
    u = (url or "").strip()
    if not u:
        return ("site", (site or "").strip().lower())
    u = re.sub(r"^https?://", "", u, flags=re.I)
    u = re.sub(r"^www\.", "", u, flags=re.I)
    return ("url", u.rstrip("/").lower())

def _identity_summary(findings):
    accounts = {}
    for u, r in findings["identity"].items():
        for tkey in ("sherlock", "maigret"):
            for h in r.get(tkey, {}).get("hits", []):
                if not (h.get("url") or h.get("site")):
                    continue
                k = _acct_key(h.get("url"), h.get("site"))
                accounts.setdefault(k, {"site": h.get("site"), "url": h.get("url"),
                                        "via": set(), "user": u})
                accounts[k]["via"].add(tkey)
    return accounts

def _accounts(findings):
    """Verified+enriched list when the verify stage ran, otherwise the raw tool merge.

    Keyed off did_verify, not findings["verified"] being non-empty: under --no-verify an
    Instagram lookup alone creates that key."""
    v = findings.get("verified") or []
    if findings.get("did_verify"):
        return sorted(v, key=lambda x: (STATE_ORDER.get(x.get("state", "unknown"), 9),
                                        -len(x.get("via") or []), (x.get("site") or "").lower()))
    raw = sorted((dict(x, via=sorted(x["via"])) for x in _identity_summary(findings).values()),
                 key=lambda x: (-len(x["via"]), x["user"], x["site"] or ""))
    # Instagram enrichment can land rows here even with the verify stage off; keep them.
    known = {_acct_key(r.get("url"), r.get("site")) for r in raw}
    return [r for r in v if _acct_key(r.get("url"), r.get("site")) not in known] + raw

def _stats(findings):
    acc = _identity_summary(findings)
    reg = sum(len(r.get("holehe", {}).get("used", [])) for r in findings["email"].values())
    br = sum(len(r.get("h8mail", {}).get("breaches", [])) + len(r.get("hibp", {}).get("breaches", []))
             for r in findings["email"].values())
    subs = set()
    for r in findings["domain"].values():
        subs |= set(r.get("crtsh", {}).get("subdomains", []))
        subs |= set(r.get("chaos", {}).get("subdomains", []))
        subs |= set(r.get("virustotal", {}).get("subdomains", []) or [])
        subs |= set(r.get("theHarvester", {}).get("hosts", []))
    confirmed = sum(1 for a in acc.values() if len(a["via"]) > 1)
    ver = findings.get("verified") or []
    ver_accs = [v for v in ver if v.get("state") == "verified"]
    n_ver = len(ver_accs)
    n_av = sum(1 for v in ver_accs if v.get("avatar"))
    av_pct = round(n_av / n_ver * 100) if n_ver else 0
    return {"accounts": len(acc), "confirmed": confirmed, "registrations": reg,
            "breaches": br, "subdomains": len(subs),
            "verified": n_ver,
            "avatars": n_av, "avatar_pct": av_pct,
            "dead": sum(1 for v in ver if v.get("state") == "dead"),
            # Everything the verifier could not settle; the cards must add up to the table.
            "undecided": sum(1 for v in ver
                             if v.get("state") in ("unconfirmed", "blocked", "unknown")),
            "unreachable": sum(1 for v in ver if v.get("state") == "error"),
            "netblocked": sum(1 for v in ver if v.get("note") in ("SSLError", "ConnectionError",
                                                                 "ConnectTimeout", "ReadTimeout")),
            "did_verify": bool(findings.get("did_verify"))}

AF_HEAD = "# ==== AUTO-FINDINGS"
AF_END = "# ==== END AUTO-FINDINGS — your own notes below this line are kept ===="

def update_target(tpath, findings, ts):
    accounts = _accounts(findings)
    lines = ["", f"{AF_HEAD} ({ts}) — appended by the scanner ===="]
    if accounts:
        names = sorted({a["display_name"] for a in accounts
                        if a.get("state") == "verified" and a.get("display_name")})
        if names:
            lines.append(f"profile_names: {', '.join(names)}")
        for a in accounts:
            if a.get("state") == "verified" and a.get("description"):
                lines.append(f"profile_bio: {a['site']} -> {a['description'][:200]}")
        lines.append("# Accounts found  [state] site | url | user | tools | name:")
        for a in accounts:
            st_ = a.get("state")
            tag = f"[{STATE_LABEL.get(st_, st_)}] " if st_ else ""
            nm = f" | name={a['display_name']}" if a.get("display_name") else ""
            lines.append(f"found_account: {tag}{a['site']} | {a['url']} | user={a['user']} "
                         f"| ({','.join(a.get('via') or [])}){nm}")
    for ti in (findings.get("target_images") or []):
        for m in ti.get("matches", []):
            sc = f" {m['score']:.2f}" if m.get("score") else ""
            df = f" | deepface={m['deepface_status']}" if m.get("deepface_status") else ""
            lines.append(f"matched_target_image: [{m.get('tier', 'possible')}{sc}] {m.get('site')} | {m.get('url')} | user={m.get('user')} (matched {ti.get('filename')}){df}")
    for i, g in enumerate(findings.get("face_groups") or [], 1):
        lines.append(f"same_face: #{i} | " + " | ".join(f"{x.get('site')} {x.get('url')}" for x in g["members"]))
    for e, r in findings["email"].items():
        used = r.get("holehe", {}).get("used", [])
        if used:
            lines.append(f"email_registered: {e} -> {', '.join(used)}")
        br = r.get("h8mail", {}).get("breaches", [])
        if br:
            lines.append(f"email_breach: {e} -> {len(br)} record(s)")
        hb = r.get("hibp", {}).get("breaches", [])
        if hb:
            lines.append(f"email_hibp: {e} -> {', '.join(str(b.get('name')) for b in hb[:20])}")
        gv = r.get("gravatar", {})
        if gv.get("found"):
            lines.append(f"gravatar: {e} -> {gv.get('profile_url')} (name={gv.get('display_name')})")
    for u, ig in (findings.get("instagram") or {}).items():
        if ig.get("ok"):
            lines.append(f"instagram: @{u} | name={ig.get('full_name')} | followers={ig.get('followers')} "
                         f"| private={ig.get('is_private')} | url={ig.get('external_url') or '-'}")
    for p in findings.get("phone", []):
        nv = p.get("numverify", {})
        if nv and not nv.get("skipped"):
            lines.append(f"phone_info: {p.get('number')} -> {nv.get('country_name')} / "
                         f"{nv.get('carrier') or 'unknown carrier'} / {nv.get('line_type')}")
    for d, r in findings["domain"].items():
        em = r.get("theHarvester", {}).get("emails", [])
        if em:
            lines.append(f"domain_emails: {d} -> {', '.join(em[:20])}")
    # Collapse whitespace: a newline inside a scraped title or bio would land in the .txt
    # as a standalone "domain: …" line that parse_target reads back on the next run.
    lines = [l if (not l or l.startswith("#")) else re.sub(r"\s+", " ", l).strip()
             for l in lines]

    lines.append(AF_END)

    # Replace the previous block rather than stacking a second one. The block is delimited
    # at BOTH ends so operator notes below it survive the next scan.
    prev = tpath.read_text(encoding="utf-8", errors="replace")
    start = prev.find("\n" + AF_HEAD)
    if start == -1:
        body, tail = prev.rstrip("\n"), ""
    else:
        body = prev[:start].rstrip("\n")
        rest = prev[start:]
        cut = rest.find(AF_END)
        # A block written before an end marker existed has no delimiter to trust:
        # header to EOF is ours.
        tail = rest[cut + len(AF_END):].lstrip("\n") if cut != -1 else ""
    text = body + "\n" + "\n".join(lines) + "\n"
    if tail:
        text += "\n" + tail.rstrip("\n") + "\n"
    tpath.write_text(text, encoding="utf-8")

# ---------------- HTML report ----------------
CSS = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1b1b19;--mut:#6b6b66;--line:#e3e3de;--accent:#b5502a;--good:#2f7d4f;--warn:#a8761b;--bad:#b3352c}
@media (prefers-color-scheme:dark){:root{--bg:#16171a;--card:#1e2024;--fg:#e9e9e6;--mut:#9a9a94;--line:#2e3136;--accent:#e08256;--good:#59b37f;--warn:#d1a04a;--bad:#e0705f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:26px;margin:0 0 4px} h2{font-size:18px;margin:34px 0 12px;padding-bottom:7px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:20px 0 8px;color:var(--accent);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.sub{color:var(--mut);font-size:13px;margin-bottom:22px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:18px 0 8px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .n{font-size:26px;font-weight:650;line-height:1.1} .card .l{color:var(--mut);font-size:12px;margin-top:3px}
.box{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
table{width:100%;border-collapse:collapse;font-size:13.5px} th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
.tw{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
.tag{display:inline-block;font-size:11px;padding:2px 7px;border-radius:99px;border:1px solid var(--line);color:var(--mut);margin-right:4px}
.tag.ok{color:var(--good);border-color:var(--good)} .tag.warn{color:var(--warn);border-color:var(--warn)} .tag.bad{color:var(--bad);border-color:var(--bad)}
img.av{width:34px;height:34px;border-radius:50%;object-fit:cover;display:block;background:var(--line)}
.noav{width:34px;height:34px;border-radius:50%;background:var(--line)}
.nm{font-weight:600} .bio{color:var(--mut);font-size:12.5px;display:block;margin-top:2px}
tr.dead td{opacity:.5}
.kv{display:grid;grid-template-columns:180px 1fr;gap:6px 14px;font-size:14px} .kv div:nth-child(odd){color:var(--mut)}
.mut{color:var(--mut)} code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;background:rgba(128,128,128,.13);padding:1px 5px;border-radius:4px}
input[type=search]{width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);font-size:14px;margin:10px 0}
ul{margin:6px 0 6px 18px;padding:0} li{margin:2px 0}
details summary{cursor:pointer;color:var(--mut);font-size:13px}
"""

def _e(x):
    return html.escape("" if x is None else str(x))

def _href(u):
    """An href value, or '#' when the scheme is not http(s).

    html.escape() stops markup injection but passes javascript: through as a valid attribute."""
    u = "" if u is None else str(u)
    return _e(u) if re.match(r"^https?://", u, re.I) else "#"

def _img(u):
    """Only the JPEG data URIs this program generates itself may become an <img src>."""
    u = "" if u is None else str(u)
    return u if u.startswith("data:image/jpeg;base64,") and re.fullmatch(r"[A-Za-z0-9+/=]+", u[23:]) else ""

def write_html_report(findings, tpath, ts):
    accounts = _accounts(findings)
    st = _stats(findings)
    inp = findings["input"]
    derived = set(inp.get("_derived", []))
    o = []
    a = o.append
    a(f"<!doctype html><html><head><meta charset='utf-8'>")
    a(f"<meta name='viewport' content='width=device-width,initial-scale=1'>")
    a(f"<title>OSINT Report — {_e(tpath.stem)}</title><style>{CSS}</style></head><body><div class='wrap'>")
    a(f"<h1>OSINT Report — {_e(inp['name'][0] if inp.get('name') else tpath.stem)}</h1>")
    a(f"<div class='sub'>Generated {_e(ts)} · target file <code>{_e(tpath.name)}</code>"
      + (f" · API sources: {_e(', '.join(findings.get('api_keys_active') or []))}" if findings.get("api_keys_active") else "")
      + "</div>")

    cards = [(st["accounts"], "accounts found")]
    # Each card names the state it counts; verified + undecided + missing + unreachable
    # equals the number of rows in the table.
    cards += ([(st["verified"], "verified live"),
               (f"{st.get('avatars', 0)}/{st.get('verified', 0)} ({st.get('avatar_pct', 0)}%)", "avatars captured"),
               (st["undecided"], "undecided"),
               (st["dead"], "confirmed missing"), (st["unreachable"], "unreachable here")]
              if st["did_verify"] else [(st["confirmed"], "confirmed by 2 tools")])
    cards += [(st["registrations"], "site registrations"), (st["breaches"], "breach records"),
              (st["subdomains"], "subdomains")]
    a("<div class='cards'>")
    for n, l in cards:
        a(f"<div class='card'><div class='n'>{n}</div><div class='l'>{l}</div></div>")
    a("</div>")

    # 1 input
    a("<h2>1 · Input</h2><div class='box'><div class='kv'>")
    labels = {"name": "Name", "email": "E-mail", "phone": "Phone", "domain": "Domain", "file": "File", "image": "Target Image", "notes": "Notes"}
    found_mail = set(inp.get("_derived_emails") or [])
    csrc = findings.get("correlation_sources") or {}
    for k in ("name", "email", "phone", "domain", "file", "image", "notes"):
        if not inp.get(k):
            continue
        if k == "email":
            # Correlation appends discoveries to the same list; split them out and say
            # where each came from.
            given = [e for e in inp[k] if e not in found_mail]
            if given:
                a(f"<div>E-mail (given)</div><div>{_e(', '.join(given))}</div>")
            if found_mail:
                a("<div>E-mail (discovered)</div><div>" + "<br>".join(
                    f"{_e(e)} <span class='mut'>— {_e(csrc.get(e, 'found during the scan'))}</span>"
                    for e in sorted(found_mail)) + "</div>")
            continue
        a(f"<div>{labels[k]}</div><div>{_e(', '.join(inp[k]))}</div>")
    given_u = [u for u in inp.get("username", []) if u not in derived]
    if given_u:
        a(f"<div>Usernames (given)</div><div>{_e(', '.join(given_u))}</div>")
    if derived:
        a(f"<div>Usernames (derived)</div><div>{_e(', '.join(sorted(derived)))} "
          f"<span class='mut'>— generated from the name / e-mail</span></div>")
    a("</div></div>")

    # 2 accounts & visual intelligence
    target_imgs = [ti for ti in (findings.get("target_images") or []) if not ti.get("error")]
    target_img_errors = [ti for ti in (findings.get("target_images") or []) if ti.get("error")]
    has_target_visuals = bool(target_imgs or target_img_errors or inp.get("image"))

    names, bios, mails = {}, [], set()
    for r in accounts:
        if r.get("state") != "verified":
            continue
        if r.get("display_name"):
            names.setdefault(r["display_name"], []).append(r.get("site") or "")
        if r.get("description"):
            bios.append((r.get("site") or "", r["description"]))
        mails |= set(r.get("emails") or [])
    photo_groups = group_by_photo(accounts) if st["did_verify"] else []

    if st["did_verify"] or has_target_visuals:
        a("<h2>2 · Visual & Identity Intelligence</h2>")

        # 2.1 operator reference images
        a("<div class='box' style='margin-bottom:16px'>")
        a("<div style='font-size:14px;font-weight:600;margin-bottom:10px;color:var(--accent);font-family:ui-monospace,SFMono-Regular,Menlo,monospace'>"
          "2.1 · Operator reference images</div>")
        if target_imgs:
            a("<div class='kv'>")
            for ti in target_imgs:
                fn = ti.get("filename") or ti.get("source")
                t_src = ti.get("source")
                dim = ti.get("dimensions", "")
                sha = ti.get("sha256", "")
                matches = ti.get("matches") or []

                thumb_html = (f"<img src='{_img(ti.get('thumb'))}' style='max-width:96px;max-height:96px;border-radius:6px;"
                              f"border:1px solid var(--line);vertical-align:top;margin-right:12px;float:left'>" if ti.get("thumb") else "")
                info_html = (f"<div>{thumb_html}<div>"
                             f"<b>{_e(fn)}</b>"
                             + (f" <span class='mut'>({_e(dim)})</span>" if dim else "")
                             + f"<br><span class='mut' style='font-size:11px'>SHA-256: <code>{_e(sha[:16])}…</code></span>"
                             + (f"<br><span class='mut' style='font-size:11px'>Source: {_e(t_src[:60])}</span>" if ti.get("is_url") else "")
                             + "</div><div style='clear:both'></div></div>")
                a(f"<div>Reference Image</div>{info_html}")

                if matches:
                    m_bits = []
                    for m in matches:
                        tier, score = m.get("tier"), m.get("score") or 0
                        if tier == "strong":
                            tag_cls, tag_txt = "ok", "strong match (byte-identical)"
                        elif tier == "face":
                            tag_cls, tag_txt = ("ok" if score >= FACE_STRONG else "warn"), f"face match (cosine {score:.2f})"
                        elif tier == "similar":
                            tag_cls, tag_txt = "warn", f"visually similar (CLIP {score:.2f})"
                        else:
                            tag_cls, tag_txt = "warn", "possible match (perceptual)"
                        df = m.get("deepface_status")
                        df_tag = ""
                        if df == "confirmed":
                            df_tag = " <span class='tag ok'>DeepFace confirms</span>"
                        elif df == "disputed":
                            which = ", ".join(r["model"] for r in (m.get("deepface_models") or [])
                                              if not r.get("verified"))
                            df_tag = (f" <span class='tag bad'>DeepFace does not confirm"
                                      + (f" ({_e(which)})" if which else "") + "</span>")
                        elif df == "abstained":
                            df_tag = " <span class='tag'>DeepFace saw no face</span>"
                        av_html = (f"<img class='av' style='display:inline-block;vertical-align:middle;margin-right:6px;width:28px;height:28px' "
                                   f"src='{_img(m.get('avatar'))}' alt=''>" if m.get("avatar") else "")
                        site_link = f"<a href='{_href(m.get('url'))}' target='_blank' rel='noopener'><b>{_e(m.get('site'))}</b></a>"
                        user_str = f" @{_e(m.get('user'))}" if m.get("user") else ""
                        name_str = f" ({_e(m.get('display_name'))})" if m.get("display_name") else ""
                        kind_str = f" [{_e(m.get('kind'))}]" if m.get("kind") == "cover" else ""
                        m_bits.append(f"<div style='margin-bottom:6px'>{av_html}{site_link}{user_str}{name_str}{kind_str} "
                                      f"<span class='tag {tag_cls}'>{tag_txt}</span>{df_tag}</div>")
                    a(f"<div>Matched Accounts <span class='tag ok'>{len(matches)} match(es)</span></div><div>{''.join(m_bits)}</div>")
                else:
                    a("<div>Matched Accounts</div><div><span class='mut'>No direct photo match found in scanned profile avatars. "
                      "Use the reverse image search links below to discover web footprint.</span></div>")

                rev_links = ti.get("reverse_links") or []
                if rev_links:
                    r_html = " · ".join(f"<a href='{_href(u)}' target='_blank' rel='noopener'>{_e(n)}</a>" for n, u in rev_links)
                    note = ("Opens reverse search query at target engine" if ti.get("is_url")
                            else "Upload / drag-and-drop your local file into the search engine portal")
                    a(f"<div>Reverse Image Search</div><div>{r_html}<br><span class='mut'>{note}</span></div>")
            a("</div>")
        elif target_img_errors:
            a("<div class='kv'>")
            for err in target_img_errors:
                a(f"<div>Reference Image Error</div><div><span class='tag warn'>{_e(err.get('filename'))}</span>: {_e(err.get('error'))}</div>")
            a("</div>")
        else:
            a("<div class='mut' style='padding:4px 0'>No reference image provided. "
              "Add <code>image: /path/to/target.jpg</code> (or URL) to your target profile, "
              "or pass <code>--image &lt;path&gt;</code> on the command line to match against discovered accounts.</div>")
        vis = findings.get("vision") or {}
        a("<div class='kv'>")
        if vis.get("status") == "ran":
            eng = " · ".join(f"{k}: {_e(v)}" for k, v in (vis.get("engine") or {}).items())
            conf = vis.get("deepface_confirms") or []
            df_line = ""
            if (vis.get("ran") or {}).get("deepface"):
                t = {k: sum(1 for c in conf if c.get("status") == k) for k in ("confirmed", "disputed", "abstained")}
                df_line = (f"<br>DeepFace re-checked {len(conf)} InsightFace match(es): "
                           f"<span class='tag ok'>{t['confirmed']} confirmed</span>"
                           f"<span class='tag bad'>{t['disputed']} disputed</span>"
                           f"<span class='tag'>{t['abstained']} not judged</span>"
                           "<br><span class='mut'>A disputed picture is stamped "
                           f"<code>{_e(DISPUTED_MARK)}</code>. DeepFace can only agree or refuse, "
                           "it never adds a match of its own.</span>")
            elif vis.get("deepface_error"):
                df_line = f"<br><span class='mut'>DeepFace did not run: {_e(vis['deepface_error'])}</span>"
            a(f"<div>Local vision</div><div>{vis.get('faces_total', 0)} face(s) found in "
              f"{len(vis.get('images') or [])} picture(s), face threshold {_e(vis.get('threshold'))}{df_line}"
              f"<br><span class='mut'>{eng}. Runs on this machine only; cosine similarity is not identity — "
              "biometric processing needs a lawful basis (KVKK art. 6 / GDPR art. 9).</span></div>")
        else:
            a(f"<div>Local vision</div><div><span class='mut'>not run — {_e(vis.get('reason') or 'no vision stage')}. "
              "Add <code>--faces</code> / <code>--clip</code> (needs <code>dashboard/install-ml.sh</code>).</span></div>")
        a("</div></div>")

        # 2.2 pictures the scan found by itself
        a("<div class='box'>")
        a("<div style='font-size:14px;font-weight:600;margin-bottom:10px;color:var(--accent);font-family:ui-monospace,SFMono-Regular,Menlo,monospace'>"
          "2.2 · Auto-discovered profile visuals &amp; identity</div>")
        a("<div class='kv'>")
        if photo_groups:
            for g in photo_groups:
                sites = ", ".join(m.get("site") or "?" for m in g["members"])
                thumb = next((m.get("avatar") for m in g["members"] if m.get("avatar")), "")
                strong = g.get("tier") == "strong"
                claim = ("use a byte-identical picture" if strong
                         else "use what looks like the same picture")
                why = ("<span class='mut'>(strong same-person evidence — the image files are "
                       "identical, so this cannot be a coincidental resemblance)</span>" if strong
                       else "<span class='mut'>(possible same person — the images match "
                            "perceptually but are not byte-identical, so confirm by eye)</span>")
                a(f"<div>Same profile photo <span class='tag {'ok' if strong else 'warn'}'>"
                  f"{'strong' if strong else 'possible'}</span></div><div>"
                  + (f"<img class='av' style='display:inline-block;vertical-align:middle;margin-right:8px' src='{_img(thumb)}' alt=''>" if thumb else "")
                  + f"<b>{len(g['members'])} accounts</b> {claim} — {_e(sites)} " + why + "</div>")
        else:
            a("<div>Profile Photo Groups</div><div><span class='mut'>No cross-platform photo clusters identified among scanned profiles.</span></div>")
        for i, g in enumerate(findings.get("face_groups") or [], 1):
            strong = (g.get("min_score") or 0) >= FACE_STRONG
            pics = "".join(f"<img class='av' style='display:inline-block;vertical-align:middle;margin-right:4px' "
                           f"src='{_img(x['avatar'])}' alt=''>" for x in g["members"] if x.get("avatar"))
            sites = ", ".join(f"<a href='{_href(x.get('url'))}' target='_blank' rel='noopener'>{_e(x.get('site'))}</a>"
                              for x in g["members"])
            lo, hi = f"{g.get('min_score') or 0:.2f}", f"{g.get('max_score') or 0:.2f}"
            dq = (f" <span class='tag bad'>DeepFace refused {g['deepface_disputed']} link(s)</span>"
                  if g.get("deepface_disputed") else "")
            a(f"<div>Same face #{i} <span class='tag {'ok' if strong else 'warn'}'>cosine {lo}–{hi}</span>{dq}</div>"
              f"<div>{pics}<b>{len(g['members'])} accounts</b> show the same face — {sites} "
              "<span class='mut'>(local InsightFace embedding; a high score means the faces look alike, "
              "which is strong but not conclusive same-person evidence)</span></div>")

        if names:
            a("<div>Names on the profiles</div><div>" + "<br>".join(
                f"<b>{_e(n)}</b> <span class='mut'>— {_e(', '.join(sorted(set(v))))}</span>"
                for n, v in sorted(names.items(), key=lambda kv: -len(kv[1]))) + "</div>")
        if mails:
            a(f"<div>E-mails shown publicly</div><div>{_e(', '.join(sorted(mails)))}</div>")

        by_pic = {}
        for r in accounts:
            src = r.get("avatar_src")
            if not src:
                continue
            k = r.get("avatar_sha256") or src
            by_pic.setdefault(k, {"src": src, "sites": []})["sites"].append(r.get("site") or "?")
        for pic in by_pic.values():
            links = " · ".join(f"<a href='{_href(u)}' target='_blank' rel='noopener'>{_e(n)}</a>"
                               for n, u in reverse_image_links(pic["src"]))
            where = ", ".join(sorted(set(pic["sites"])))
            a(f"<div>Reverse image search<br><span class='mut'>({_e(where)} photo)</span></div>"
              f"<div>{links}<br><span class='mut'>Opens the picture at a search engine — "
              f"this leaves your query with that engine, not with the target.</span></div>")

        by_cover = {}
        for r in accounts:
            csrc = r.get("cover_url")
            if not csrc:
                continue
            by_cover.setdefault(csrc, {"src": csrc, "thumb": r.get("cover_thumb"), "sites": []})["sites"].append(r.get("site") or "?")
        for cov in by_cover.values():
            links = " · ".join(f"<a href='{_href(u)}' target='_blank' rel='noopener'>{_e(n)}</a>"
                               for n, u in reverse_image_links(cov["src"]))
            where = ", ".join(sorted(set(cov["sites"])))
            cov_img = f"<img src='{_img(cov['thumb'])}' style='max-height:42px;vertical-align:middle;margin-right:8px;border-radius:4px;border:1px solid #444'>" if cov.get("thumb") else ""
            a(f"<div>Reverse image search<br><span class='mut'>({_e(where)} cover)</span></div>"
              f"<div>{cov_img}{links}<br><span class='mut'>Opens the profile banner/cover at a search engine — "
              f"useful for identifying event photos or corporate branding.</span></div>")

        for u, ig in (findings.get("instagram") or {}).items():
            if not ig.get("ok"):
                continue
            bits = [f"<b>{_e(ig.get('full_name') or u)}</b>",
                    f"{ig.get('followers')} followers", f"{ig.get('followees')} following"]
            if ig.get("is_private"):  bits.append("<span class='tag warn'>private</span>")
            if ig.get("is_verified"): bits.append("<span class='tag ok'>verified</span>")
            if ig.get("is_business"): bits.append(f"business: {_e(ig.get('business_category') or '—')}")
            if ig.get("external_url"):
                bits.append(f"<a href='{_href(ig['external_url'])}' target='_blank' rel='noopener'>{_e(ig['external_url'])}</a>")
            a(f"<div>Instagram @{_e(u)}</div><div>" + " · ".join(bits) + "</div>")
        for site, b in bios[:8]:
            a(f"<div>{_e(site)} bio</div><div>{_e(b[:300])}</div>")
        a("</div></div>")

    a("<h2>3 · Accounts found</h2>")
    if accounts:
        if st["did_verify"]:
            a("<div class='sub'>Every URL was opened. <span class='tag ok'>verified</span> = the page loads and "
              "the handle appears in the page's own text or title — the handle merely being in the address "
              "proves nothing, since the discovery tools built that address out of it · "
              "<span class='tag bad'>does not exist</span> = false positive from "
              "the tool · <span class='tag warn'>could not confirm</span> = loads but renders with JavaScript, "
              "or a consent/bot screen answered instead of the profile — check by hand · "
              "<span class='tag warn'>blocked by site</span> = the site refused us (401/403/429); nothing "
              "follows about whether the account exists · <span class='tag'>unknown</span> = some other "
              "HTTP status we cannot read a verdict from · <span class='tag bad'>unreachable from here</span> = the request failed at "
              "network level (TLS/DNS), which on a censored connection usually means the site is blocked — "
              "not proof the account is missing.<br>Anything we could not decide was then checked "
              "against the Internet Archive — <span class='tag ok'>archived …</span> means the page "
              "was really captured on that date, so the account existed. That check asks archive.org, "
              "never the target's site, so it costs nothing in exposure. No archive record means "
              "nothing either way: most small profiles are never archived.</div>")
        def _state_cell(r):
            stt = r.get("state")
            cls = {"verified": "ok", "dead": "bad", "error": "bad", "unconfirmed": "warn",
                   "blocked": "warn"}.get(stt, "")
            cell = (f"<span class='tag {cls}'>{_e(STATE_LABEL.get(stt, stt))}</span>"
                    if stt else "<span class='mut'>—</span>")
            if r.get("note"):
                cell = cell[:-7] + f"</span> <span class='mut' title='{_e(r['note'])}'>ⓘ</span>"
            if r.get("photo_group"):
                ptier = r.get("photo_tier") or "possible"
                cell += (f" <span class='tag {'ok' if ptier == 'strong' else 'warn'}'>"
                         f"photo #{r['photo_group']} {_e(ptier)}</span>")
            if r.get("face_group"):
                cell += f" <span class='tag ok'>face #{r['face_group']}</span>"
            if r.get("face_match"):
                cell += f" <span class='tag {'ok' if r['face_match'] >= FACE_STRONG else 'warn'}'>ref face {r['face_match']:.2f}</span>"
            dfs = r.get("deepface_status")
            if dfs == "disputed":
                cell += "<span class='tag bad' title='DeepFace re-checked this match and refused it'>DeepFace disputed</span>"
            elif dfs == "confirmed":
                cell += "<span class='tag ok'>DeepFace confirmed</span>"
            elif dfs == "abstained":
                cell += "<span class='tag' title='DeepFace found no face to judge'>DeepFace n/a</span>"
            arc = r.get("archive") or {}
            if arc.get("existed"):
                cell += (f" <a href='{_href(arc.get('wayback_url'))}' target='_blank' rel='noopener'>"
                         f"<span class='tag ok'>archived {_e(arc.get('first'))}</span></a>")
            elif arc.get("note"):
                cell += f" <span class='tag' title='{_e(arc['note'])}'>archive: no data</span>"
            return cell

        def _row(r):
            stt = r.get("state")
            av = (f"<img class='av' src='{_img(r['avatar'])}' alt=''>" if r.get("avatar")
                  else "<div class='noav'></div>")
            name = r.get("display_name") or ""
            bio = (r.get("description") or "")[:120]
            prof = f"<a href='{_href(r.get('url'))}' target='_blank' rel='noopener'>"
            prof += f"<span class='nm'>{_e(name)}</span>" if name else _e(r.get("url"))
            prof += "</a>"
            if bio:
                prof += f"<span class='bio'>{_e(bio)}</span>"
            elif name:
                prof += f"<span class='bio'>{_e(r.get('url'))}</span>"
            return (f"<tr class='{'dead' if stt == 'dead' else ''}'><td>{av}</td>"
                    f"<td>{_e(r.get('site'))}</td><td>{prof}</td>"
                    f"<td><code>{_e(r.get('user'))}</code></td><td>{_state_cell(r)}</td>"
                    f"<td><span class='tag'>{_e(','.join(r.get('via') or []))}</span></td></tr>")

        # Undecided states are not findings either way and mostly repeat one site across
        # derived handles, so they are collapsed to one line per site.
        UNDECIDED = ("unconfirmed", "blocked", "unknown")
        decided = [r for r in accounts if r.get("state") not in UNDECIDED]
        undecided = [r for r in accounts if r.get("state") in UNDECIDED]

        a("<input type='search' id='q' placeholder='Filter accounts (site, name, url, username) …'>")
        a("<div class='tw'><table id='acc'><thead><tr><th></th><th>Site</th><th>Profile</th>"
          "<th>Username</th><th>State</th><th>Tools</th></tr></thead><tbody>")
        for r in decided:
            a(_row(r))
        if not decided:
            a("<tr><td colspan='6' class='mut'>No account reached a verdict; see the undecided "
              "rows below.</td></tr>")
        a("</tbody></table></div>")

        if undecided:
            by_site = {}
            for r in undecided:
                by_site.setdefault(r.get("site") or "?", []).append(r)
            a(f"<details><summary><b>Undecided: {len(undecided)} row(s) on {len(by_site)} site(s)</b> "
              "<span class='mut'>— the page opened but nothing on it tied it to this person, or the "
              "site answered with a wall. Not evidence either way; grouped by site, every handle "
              "still linked. Expand to review by hand.</span></summary>")
            a("<div class='tw'><table id='acc2'><thead><tr><th>Site</th><th>Handles tried</th>"
              "<th>Verdict per handle</th></tr></thead><tbody>")
            for site, rows in sorted(by_site.items(), key=lambda kv: (-len(kv[1]), kv[0].lower())):
                handles = " ".join(
                    f"<a href='{_href(x.get('url'))}' target='_blank' rel='noopener'>"
                    f"<code>{_e(x.get('user'))}</code></a>" for x in rows)
                verdicts = "<br>".join(_state_cell(x) for x in rows)
                a(f"<tr><td>{_e(site)}</td><td>{handles}</td><td>{verdicts}</td></tr>")
            a("</tbody></table></div></details>")

        a("<script>const q=document.getElementById('q');q.addEventListener('input',()=>{const v=q.value.toLowerCase();"
          "document.querySelectorAll('#acc tbody tr, #acc2 tbody tr').forEach(t=>{t.style.display=t.innerText.toLowerCase().includes(v)?'':'none'})});</script>")
    else:
        a("<div class='box mut'>No accounts found.</div>")

    ss = findings.get("socialscan") or {}
    ss_rows = [r for r in (ss.get("results") or []) if isinstance(r, dict)]
    if ss.get("failed") or ss.get("skipped") or ss_rows:
        a("<details><summary><b>Username / e-mail availability</b> "
          "<span class='mut'>(socialscan — \"taken\" means something is registered there)</span></summary>")
        if ss.get("failed") or ss.get("skipped"):
            a(f"<div class='box mut'>Did not run — {_e(ss.get('failed') or ss.get('skipped'))}</div>")
        else:
            taken = [r for r in ss_rows if r.get("taken") and r.get("success")]
            a("<div class='tw'><table><thead><tr><th>Query</th><th>Platform</th><th>Status</th>"
              "</tr></thead><tbody>")
            for r in sorted(taken, key=lambda x: (str(x.get("query")), str(x.get("platform")))):
                a(f"<tr><td><code>{_e(r.get('query'))}</code></td>"
                  f"<td>{_e(r.get('platform'))}</td>"
                  f"<td><span class='tag warn'>taken</span></td></tr>")
            if not taken:
                a("<tr><td colspan='3' class='mut'>Nothing registered on the platforms "
                  "socialscan checks.</td></tr>")
            a("</tbody></table></div>")
        a("</details>")

    # 3 email
    a("<h2>4 · E-mail intelligence</h2>")
    if findings["email"]:
        for e, r in findings["email"].items():
            a(f"<h3>{_e(e)}</h3><div class='box'>")
            used = r.get("holehe", {}).get("used", [])
            a("<div class='kv'>")
            a(f"<div>Registered on (holehe)</div><div>{' '.join(f'<span class=tag>{_e(u)}</span>' for u in used) if used else '<span class=mut>—</span>'}</div>")
            h8 = r.get("h8mail", {})
            br = h8.get("breaches", [])
            # "0" is only a finding when h8mail had a configured source to look in.
            if br or h8.get("sources"):
                a(f"<div>Breach records (h8mail)</div><div>{len(br)}"
                  + (f" <span class='mut'>— sources: {_e(', '.join(h8['sources']))}</span>"
                     if h8.get("sources") else "") + "</div>")
            else:
                a("<div>Breach records (h8mail)</div><div><span class='tag warn'>not checked</span> "
                  f"<span class='mut'>{_e(h8.get('note') or 'no breach source configured')}</span></div>")
            hb = r.get("hibp", {})
            if hb.get("breaches"):
                a("<div>HIBP breaches</div><div>" + ", ".join(f"{_e(b['name'])} <span class='mut'>({_e(b['date'])})</span>" for b in hb["breaches"][:20]) + "</div>")
            elif hb.get("skipped"):
                a(f"<div>HIBP</div><div class='mut'>skipped — {_e(hb['skipped'])}</div>")
            hu = r.get("hunter", {})
            if hu and not hu.get("skipped"):
                a(f"<div>Hunter.io verifier</div><div>status <b>{_e(hu.get('status'))}</b>, score {_e(hu.get('score'))}, "
                  f"webmail={_e(hu.get('webmail'))}, disposable={_e(hu.get('disposable'))}</div>")
            gv = r.get("gravatar", {})
            if gv.get("found"):
                a(f"<div>Gravatar</div><div><a href='{_href(gv.get('profile_url'))}' target='_blank' rel='noopener'>"
                  f"{_e(gv.get('display_name') or gv.get('profile_url'))}</a>"
                  + (f" · {_e(gv.get('location'))}" if gv.get("location") else "") + "</div>")
                if gv.get("accounts"):
                    a("<div>Gravatar linked accounts</div><div><ul>" + "".join(
                        f"<li>{_e(x.get('site'))}: <a href='{_href(x.get('url'))}' target='_blank' rel='noopener'>{_e(x.get('url'))}</a></li>"
                        for x in gv["accounts"][:20]) + "</ul></div>")
            a("</div></div>")
    else:
        a("<div class='box mut'>No e-mail provided.</div>")

    # 4 phone
    a("<h2>5 · Phone intelligence</h2>")
    if findings.get("phone"):
        for p in findings["phone"]:
            a(f"<h3>{_e(p.get('number'))}</h3><div class='box'><div class='kv'>")
            nv = p.get("numverify", {})
            if nv and not nv.get("skipped"):
                valid = "ok" if nv.get("valid") else "bad"
                a(f"<div>Validity (numverify)</div><div><span class='tag {valid}'>{'valid' if nv.get('valid') else 'invalid'}</span></div>")
                a(f"<div>Country</div><div>{_e(nv.get('country_name'))} ({_e(nv.get('country_code'))})</div>")
                a(f"<div>Carrier</div><div><b>{_e(nv.get('carrier') or '—')}</b></div>")
                a(f"<div>Line type</div><div>{_e(nv.get('line_type') or '—')}</div>")
                a(f"<div>Formats</div><div>{_e(nv.get('international_format'))} · local {_e(nv.get('local_format'))}</div>")
            elif nv.get("skipped"):
                a(f"<div>numverify</div><div class='mut'>skipped — {_e(nv['skipped'])}</div>")
            pi = p.get("phoneinfoga", {})
            dc = pi.get("dork_counts", {})
            if dc:
                a("<div>Footprint dorks</div><div>" + ", ".join(f"{_e(k)}={v}" for k, v in dc.items()) + "</div>")
            a("</div>")
            socials = pi.get("dorks", {}).get("social", [])
            if socials:
                a("<details><summary>Manual check links (social media)</summary><ul>" + "".join(
                    f"<li><a href='{_href(u)}' target='_blank' rel='noopener'>{_e(u[:110])}…</a></li>" for u in socials[:10]) + "</ul></details>")
            disp = pi.get("dorks", {}).get("disposable", [])
            if disp:
                a(f"<p class='mut'>⚠️ {len(disp)} disposable / SMS-receive site checks available — use them to tell whether the number is a burner.</p>")
            a("</div>")
    else:
        a("<div class='box mut'>No phone provided.</div>")

    # 5 domain
    a("<h2>6 · Domain &amp; infrastructure</h2>")
    if findings["domain"]:
        for d, r in findings["domain"].items():
            th = r.get("theHarvester", {}); dt = r.get("dnstwist", {}); vt = r.get("virustotal", {})
            ch = r.get("chaos", {}); cr = r.get("crtsh", {}); hu = r.get("hunter", {})
            a(f"<h3>{_e(d)}</h3><div class='box'><div class='kv'>")
            a(f"<div>E-mails (theHarvester)</div><div>{_e(', '.join(th.get('emails', [])[:40])) or '<span class=mut>—</span>'}</div>")
            if th.get("failed"):
                a(f"<div>theHarvester</div><div><span class='tag warn'>did not run</span> "
                  f"{_e(th['failed'])}</div>")
            else:
                a(f"<div>Hosts (theHarvester)</div><div>{len(th.get('hosts', []))}</div>")
            # Name the source that actually answered: the certspotter fallback must not
            # be reported under crt.sh's name.
            if cr.get("skipped"):
                a(f"<div>Certificate transparency</div><div><span class='tag warn'>no answer</span> "
                  f"{_e(cr['skipped'])}</div>")
            else:
                src = cr.get("tool", "crt.sh")
                note = f" <span class='mut'>— {_e(cr['note'])}</span>" if cr.get("note") else ""
                a(f"<div>Subdomains ({_e(src)})</div><div>{len(cr.get('subdomains', []))}{note}</div>")
            if vt and not vt.get("skipped"):
                a(f"<div>VirusTotal reputation</div><div>{_e(vt.get('reputation'))} · registrar {_e(vt.get('registrar') or '—')}</div>")
                if vt.get("dns"):
                    a("<div>DNS records</div><div>" + "<br>".join(
                        f"<b>{_e(t)}</b> {_e(', '.join(v[:6]))}" for t, v in list(vt["dns"].items())[:8]) + "</div>")
                if vt.get("resolutions"):
                    a("<div>Historic IPs</div><div>" + _e(", ".join(str(x["ip"]) for x in vt["resolutions"][:12])) + "</div>")
                if vt.get("subdomains"):
                    a(f"<div>VT subdomains</div><div>{len(vt['subdomains'])}</div>")
            elif vt.get("skipped"):
                a(f"<div>VirusTotal</div><div class='mut'>skipped — {_e(vt['skipped'])}</div>")
            if ch.get("subdomains"):
                a(f"<div>Chaos subdomains</div><div>{len(ch['subdomains'])}</div>")
            elif ch.get("skipped"):
                a(f"<div>Chaos</div><div class='mut'>skipped — {_e(ch['skipped'])}</div>")
            if hu and not hu.get("skipped"):
                a(f"<div>Hunter.io</div><div>pattern <code>{_e(hu.get('pattern'))}</code> · org {_e(hu.get('organization') or '—')} · {len(hu.get('emails', []))} e-mail(s)</div>")
            elif hu.get("skipped"):
                a(f"<div>Hunter.io</div><div class='mut'>skipped — {_e(hu['skipped'])}</div>")
            a(f"<div>Look-alike domains</div><div>{len(dt.get('registered', []))}</div>")
            a("</div>")
            allsubs = sorted(set(cr.get("subdomains", [])) | set(ch.get("subdomains", [])) | set(vt.get("subdomains") or []))
            if allsubs:
                a(f"<details><summary>All subdomains ({len(allsubs)})</summary><ul>" +
                  "".join(f"<li><code>{_e(s)}</code></li>" for s in allsubs[:400]) + "</ul></details>")
            if hu.get("emails"):
                a("<div class='tw' style='margin-top:10px'><table><thead><tr><th>E-mail</th><th>Name</th><th>Position</th><th>Confidence</th></tr></thead><tbody>"
                  + "".join(f"<tr><td>{_e(x['value'])}</td><td>{_e(x.get('name'))}</td><td>{_e(x.get('position'))}</td><td>{_e(x.get('confidence'))}</td></tr>"
                            for x in hu["emails"][:50]) + "</tbody></table></div>")
            if dt.get("registered"):
                a(f"<details><summary>Look-alike domains ({len(dt['registered'])})</summary><ul>" +
                  "".join(f"<li><code>{_e(x.get('domain'))}</code> <span class='mut'>({_e(x.get('fuzzer'))})</span></li>"
                          for x in dt["registered"][:100]) + "</ul></details>")
            a("</div>")
    else:
        a("<div class='box mut'>No domain provided.</div>")

    # 6 metadata
    a("<h2>7 · File metadata</h2>")
    if findings["metadata"]:
        for m in findings["metadata"]:
            if m.get("skipped"):
                a(f"<div class='box mut'>{_e(m.get('file'))}: skipped ({_e(m['skipped'])})</div>")
            else:
                meta = m.get("meta", {})
                sm = meta.get("_summary") or _summarize_exif(meta)
                a(f"<div class='box'><b>{_e(m.get('file'))}</b> <span class='mut'>({_e(m.get('tool'))}, {len(meta)} fields)</span>")
                if sm:
                    a("<div class='kv' style='margin-top:8px'>")
                    for k in ("Device", "Software", "Creator", "DateTime", "GPS"):
                        if k in sm:
                            val_html = _e(sm[k])
                            if k == "GPS" and "GPSLatitude" in sm and "GPSLongitude" in sm:
                                val_html += f" · 📍 <a href='https://www.google.com/maps?q={_e(sm['GPSLatitude'])},{_e(sm['GPSLongitude'])}' target='_blank' rel='noopener'>Open map</a>"
                            a(f"<div><b>{_e(k)}</b></div><div>{val_html}</div>")
                    a("</div>")
                elif "GPSLatitude" in meta and "GPSLongitude" in meta:
                    lat, lon = meta.get("GPSLatitude"), meta.get("GPSLongitude")
                    if lat is not None and lon is not None:
                        a(f"<p>📍 <a href='https://www.google.com/maps?q={_e(lat)},{_e(lon)}' target='_blank' rel='noopener'>Open location on the map</a></p>")

                if meta.get("_thumbnail"):
                    a(f"<div style='margin-top:12px;padding:8px;background:rgba(255,255,255,0.04);border-radius:6px'>"
                      f"<b>Embedded EXIF Thumbnail</b> <span class='mut'>(often uncropped/unedited camera original):</span><br>"
                      f"<img src='{meta['_thumbnail']}' style='max-height:160px;margin-top:6px;border-radius:4px;border:1px solid #555'>"
                      f"</div>")

                a("<details style='margin-top:8px'><summary>All metadata fields</summary><div class='kv' style='margin-top:8px'>"
                  + "".join(f"<div>{_e(k)}</div><div>{_e(str(v)[:200])}</div>" for k, v in list(meta.items())[:200] if not str(k).startswith("_")) + "</div></details></div>")
    else:
        a("<div class='box mut'>No file provided.</div>")

    # ---- 8 · curated manual pivots -------------------------------------------------
    inp = findings["input"]
    pivot_entities = []
    for kind, key in (("username", "username"), ("email", "email"), ("domain", "domain"),
                      ("phone", "phone"), ("name", "name")):
        for v in (inp.get(key) or [])[:3]:
            pivot_entities.append((kind, v))
    if pivot_entities:
        a("<h2>8 · Where to look next (curated, not automated)</h2>")
        a("<div class='sub'>Resource list from the OSINT Framework dataset (MIT). "
          "<b>Nothing here was fetched</b> — these are links, so no request leaves your machine "
          "until you click one, and none of them can add a false positive to the findings above. "
          "<span class='tag ok'>passive</span> = the resource queries its own data. "
          "<span class='tag warn'>active</span> = clicking it touches the target's own platform "
          "and can show up in their logs.</div>")
        for kind, value in pivot_entities:
            pre = prefilled(kind, value)
            res = pivots_for(kind, 8, value=value)
            if not pre and not res:
                continue
            a(f"<details><summary><b>{_e(kind)}</b> · <code>{_e(value)}</code> "
              f"<span class='mut'>({len(pre)} ready-made + {len(res)} curated)</span></summary>")
            if pre:
                a("<div class='box'><b>Ready to click — already filled in with this value</b><ul>"
                  + "".join(f"<li><a href='{_href(u['url'])}' target='_blank' rel='noopener'>{_e(u['name'])}</a></li>"
                            for u in pre) + "</ul></div>")
            if res:
                a("<div class='tw'><table><thead><tr><th>Resource</th><th>OPSEC</th><th>Cost</th>"
                  "<th>What it is</th></tr></thead><tbody>")
                for x in res:
                    cls = {"passive": "ok", "active": "warn"}.get(x["opsec"], "")
                    reg = " <span class='tag'>signup</span>" if x["reg"] else ""
                    note = f"<span class='bio'>{_e(x['note'][:150])}</span>" if x["note"] else ""
                    a(f"<tr><td><a href='{_href(x['url'])}' target='_blank' rel='noopener'>{_e(x['name'])}</a>{reg}</td>"
                      f"<td><span class='tag {cls}'>{_e(x['opsec'])}</span></td>"
                      f"<td class='mut'>{_e(x['pricing'])}</td>"
                      f"<td>{_e(x['desc'][:120])}{note}</td></tr>")
                a("</tbody></table></div>")
            a("</details>")

    # ---- 9 · what this scan itself exposed -----------------------------------------
    op = findings.get("opsec") or {}
    if op:
        th, tp = op.get("target_hosts") or {}, op.get("third_parties") or {}
        a("<h2>9 · Your own footprint from this scan</h2><div class='box'>")
        a("<div class='kv'>")
        eg = op.get("egress") or {}
        if eg.get("error"):
            route = f"<span class='mut'>could not determine ({_e(eg['error'])})</span>"
        elif eg.get("tor"):
            route = (f"<span class='tag ok'>Tor</span> exit {_e(eg.get('ip'))} "
                     f"<span class='mut'>({_e(eg.get('country'))})</span>")
        elif eg.get("mullvad"):
            route = (f"<span class='tag ok'>Mullvad VPN</span> exit {_e(eg.get('ip'))} "
                     f"<span class='mut'>({_e(eg.get('country'))}) — your ISP address was not used</span>")
        else:
            route = (f"<span class='tag bad'>direct</span> {_e(eg.get('ip'))} "
                     f"<span class='mut'>({_e(eg.get('org'))}, {_e(eg.get('country'))}) — "
                     f"every request below is attributable to this connection</span>")
        a(f"<div>How this scan left your machine</div><div>{route}</div>")
        eg2 = op.get("egress_end") or {}
        if op.get("egress_changed"):
            a("<div>Exit at the end of the scan</div><div><span class='tag bad'>CHANGED</span> "
              f"{_e(eg2.get('ip'))} <span class='mut'>({_e(eg2.get('country'))}) — the route above did "
              "not hold for the whole run. Requests made after it changed left over a different "
              "connection, possibly your own; treat this scan as exposed.</span></div>")
        elif eg2 and not eg2.get("error"):
            a("<div>Exit at the end of the scan</div><div><span class='tag ok'>unchanged</span> "
              f"<span class='mut'>{_e(eg2.get('ip'))} — the same exit held from start to finish</span></div>")
        if op.get("lockdown") is not None:
            a("<div>Mullvad kill-switch</div><div>"
              + ("<span class='tag ok'>on</span> <span class='mut'>if the VPN drops, traffic is blocked "
                 "rather than leaked</span>" if str(op["lockdown"]).startswith("on") else
                 "<span class='tag bad'>off</span> <span class='mut'>if the VPN drops mid-scan, traffic "
                 "continues over your ISP (run without --no-lockdown to have the scan enable it)</span>")
              + "</div>")
        a(f"<div>Target platforms contacted directly</div><div><b>{sum(th.values())}</b> request(s) "
          f"to <b>{len(th)}</b> host(s)"
          + (f" <span class='mut'>— {_e(', '.join(sorted(th)[:12]))}</span>" if th else "") + "</div>")
        a(f"<div>Third parties told about the target</div><div>"
          + (_e(", ".join(f"{k} ({v})" for k, v in sorted(tp.items()))) if tp
             else "<span class='mut'>none</span>")
          + "<br><span class='mut'>These services received the identifiers you searched for, "
            "tied to your API keys.</span></div>")
        if op.get("tools"):
            a(f"<div>Tools that contacted platforms</div><div>{_e(', '.join(op['tools']))}"
              "<br><span class='mut'>sherlock and maigret probe hundreds of sites per username; "
              "that traffic is not counted above and is not routed through Tor unless proxychains "
              "is installed.</span></div>")
        a("</div></div>")

    steps = ["<li>Start with the <span class='tag ok'>verified</span> accounts — those pages were opened "
             "and really carry this username.</li>",
             "<li><span class='tag warn'>could not confirm</span> usually means the site renders with "
             "JavaScript (TikTok, Instagram); open those by hand.</li>"]
    if st.get("unreachable"):
        why = (f" {st['netblocked']} of them failed at TLS/DNS level, which is what ISP-level blocking "
               f"looks like." if st.get("netblocked") else "")
        steps.append(f"<li><b>{st['unreachable']} account(s) could not be reached from this network.</b>{why} "
                     f"They are unresolved, not disproved — settle them over Tor: "
                     f"<code>osint &lt;profile.txt&gt; --tor</code></li>")
    arch = sum(1 for r in accounts if (r.get("archive") or {}).get("existed"))
    if arch:
        steps.append(f"<li><b>{arch} undecided account(s) were found in the Internet Archive</b> — "
                     "click the <span class='tag ok'>archived</span> badge to see the captured page.</li>")
    dp = findings.get("deep")
    if dp:
        a("<h2>10 · Deep scan (SpiderFoot)</h2><div class='box'>")
        if dp.get("skipped"):
            a(f"<div class='mut'>Skipped — {_e(dp['skipped'])}</div>")
        elif dp.get("failed"):
            a(f"<div><span class='tag warn'>did not run</span> seed <code>{_e(dp.get('seed',''))}</code> "
              f"— {_e(dp['failed'])}</div>"
              "<div class='mut' style='margin-top:6px'>Nothing below was measured. Install the image with "
              "<code>docker pull smicallef/spiderfoot</code>, then re-run.</div>")
        else:
            a(f"<div><span class='tag ok'>ran</span> seed <code>{_e(dp.get('seed',''))}</code></div>")
            if dp.get("out_tail"):
                a("<details style='margin-top:8px'><summary>raw output (tail)</summary>"
                  f"<pre style='white-space:pre-wrap;overflow-x:auto'>{_e(dp['out_tail'])}</pre></details>")
        a("</div>")

    steps.append("<li>Use the phone footprint links to check the number by hand on social platforms.</li>")
    tips = []
    if not dp:
        tips.append("<code>--deep</code> for a SpiderFoot sweep")
    if (findings.get("input") or {}).get("_depth_used", 1) < 2:
        tips.append("<code>--depth 2</code> to follow newly discovered e-mails")
    if tips:
        steps.append("<li>Re-run with " + ", or ".join(tips) + ".</li>")
    a(f"<h2>{11 if dp else 10} · Next steps</h2><div class='box'><ul>" + "".join(steps) + "</ul></div>")
    a(f"<p class='mut' style='margin-top:30px'>Target profile (raw findings appended at the end): "
      f"<code>{_e(tpath.name)}</code> — in this same folder.</p>")
    a("</div></body></html>")
    H = tpath.parent / f"{tpath.stem}.html"
    H.write_text("\n".join(o), encoding="utf-8")
    return H

if __name__ == "__main__":
    import atexit, signal
    atexit.register(_run_restore)
    for _sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(_sig, lambda *_: sys.exit(143))
    main()
