#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KARGU-OSINT · interactive target intake wizard (English).

Asks for every known detail one question at a time, validates the answers,
creates one folder per case under cases/ and (optionally) starts the scan.

Usage:
    kargu-new                 # full interactive wizard
    kargu-new --name mycase   # pre-set the case name
    kargu-new --no-run        # only build the target file, do not scan
"""
import argparse, datetime, os, pathlib, re, subprocess, sys

HOME = pathlib.Path.home()
# Same anchor as osint_run.py: this file's own directory, overridable with OSINT_HOME.
OSINT = pathlib.Path(os.environ.get("OSINT_HOME") or pathlib.Path(__file__).resolve().parent)
CASES = OSINT / "cases"     # every scan gets ONE folder: <case>.txt + .html + .json
CASES.mkdir(parents=True, exist_ok=True)

TTY = sys.stdout.isatty()
def c(code, s):  return f"\033[{code}m{s}\033[0m" if TTY else s
B  = lambda s: c("1", s)
DIM= lambda s: c("2", s)
CY = lambda s: c("1;36", s)
YL = lambda s: c("33", s)
GN = lambda s: c("32", s)
RD = lambda s: c("31", s)

SKIP = {"", "no", "n", "-", "none", "skip", "yok", "hayir", "hayır"}

# ---------------- validators ----------------
EMAIL_RE  = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9\-.]{1,253}\.[A-Za-z]{2,}$")
USER_RE   = re.compile(r"^[A-Za-z0-9._\-]{2,40}$")

def v_email(x):
    return (True, x.lower()) if EMAIL_RE.match(x) else (False, "not a valid e-mail address")

DEFAULT_CC = os.environ.get("OSINT_DEFAULT_CC", "90")   # Turkey (+90)

def v_phone(x):
    # A leading 0 is the national trunk prefix: "0532..." must become "+90532...", not "+0532...".
    n = re.sub(r"[^\d+]", "", x)
    if not n:
        return (False, "too short for a phone number (use +90...)")
    if not n.startswith("+"):
        if n.startswith("00"):  n = "+" + n[2:]
        elif n.startswith("0"): n = "+" + DEFAULT_CC + n[1:]
        else:                   n = "+" + n
    return (True, n) if len(re.sub(r"\D", "", n)) >= 8 else (False, "too short for a phone number (use +90...)")

def v_domain(x):
    x = x.lower().strip().rstrip("/")
    x = re.sub(r"^https?://", "", x).split("/")[0]
    return (True, x) if DOMAIN_RE.match(x) else (False, "not a valid domain (example.com)")

def v_user(x):
    x = x.strip().lstrip("@")
    return (True, x) if USER_RE.match(x) else (False, "usernames may only contain letters, digits, . _ -")

def v_file(x):
    p = pathlib.Path(x.strip().strip("'\"")).expanduser()
    return (True, str(p)) if p.exists() else (False, f"file not found: {p}")

def v_any(x):
    return (True, x.strip())

def v_image(x):
    x = x.strip().strip("'\"")
    if x.startswith(("http://", "https://")):
        return (True, x)
    p = pathlib.Path(x).expanduser()
    if not p.is_file():
        return (False, f"file not found: {p}")
    if p.suffix.lower() not in IMAGE_EXTS:
        return (False, "not an image file (jpg, png, webp, bmp, gif)")
    return (True, str(p))

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}
ML_PY = OSINT / "ml" / ".venv" / "bin" / "python"   # optional local vision stack (dashboard/install-ml.sh)

# ---------------- question definitions (shared with the web UI) ----------------
FIELDS = [
    dict(key="name",     title="Full name",
         hint="First and last name of the target. Used to derive candidate usernames.",
         example="John Doe", multi=False, validator=v_any),
    dict(key="username", title="Usernames / handles",
         hint="Nicknames this person commonly uses. Separate several with commas.",
         example="johndoe, jdoe_92, jd.doe", multi=True, validator=v_user),
    dict(key="email",    title="E-mail addresses",
         hint="Any address you know. Separate several with commas.",
         example="john@gmail.com, j.doe@work.com", multi=True, validator=v_email),
    dict(key="phone",    title="Phone numbers",
         hint="International format is best. Separate several with commas.",
         example="+90 532 000 00 00", multi=True, validator=v_phone),
    dict(key="domain",   title="Domains / websites",
         hint="A personal site, company domain or e-mail domain worth mapping.",
         example="example.com, mysite.dev", multi=True, validator=v_domain),
    dict(key="file",     title="Files for metadata",
         hint="Photo or PDF paths — EXIF/GPS and author fields get extracted.",
         example="/home/user/Desktop/photo.jpg", multi=True, validator=v_file),
    dict(key="image",    title="Reference photos of the target",
         hint="Pictures of the person (paths or URLs). Matched against the profile photos the scan finds.",
         example="/home/user/Pictures/target.jpg, https://example.com/photo.jpg", multi=True, validator=v_image),
    dict(key="notes",    title="Free notes",
         hint="Anything else worth recording in the report (city, employer, age...).",
         example="Lives in Istanbul, studies CS", multi=False, validator=v_any),
]

# ---------------- prompting ----------------
def ask_field(f, idx, total):
    print()
    print(CY(f"[{idx}/{total}] {f['title']}"))
    print(DIM(f"      {f['hint']}"))
    print(DIM(f"      e.g. {f['example']}"
              + ("   ·  separate multiple values with commas" if f["multi"] else "")))
    print(DIM('      Type "no" (or press Enter) to skip this step.'))
    while True:
        try:
            raw = input(B("      > ")).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n" + YL("Cancelled.")); sys.exit(130)
        if raw.lower() in SKIP:
            print(DIM("      · skipped"))
            return []
        parts = [p.strip() for p in raw.split(",")] if f["multi"] else [raw]
        parts = [p for p in parts if p]
        good, bad = [], []
        for p in parts:
            okv, val = f["validator"](p)
            (good if okv else bad).append(val if okv else f"{p} — {val}")
        if bad:
            for b in bad:
                print(RD(f"      ! {b}"))
            if not good:
                print(DIM("      Try again, or type \"no\" to skip."))
                continue
            try:
                keep = input(YL(f"      Keep the {len(good)} valid value(s) and continue? [Y/n] ")).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n" + YL("Cancelled.")); sys.exit(130)
            if keep in ("n", "no"):
                continue
        dedup = list(dict.fromkeys(good))
        print(GN(f"      · recorded: {', '.join(dedup)}"))
        return dedup

def ask_yes(question, default=True):
    d = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            r = input(B(f"      {question} {d} ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n" + YL("Cancelled.")); sys.exit(130)
        if not r:
            return default
        if r in ("y", "yes"): return True
        if r in ("n", "no"):  return False

def slugify(s):
    tr = str.maketrans("çğıöşüÇĞİÖŞÜ", "cgiosucgiosu")
    s = re.sub(r"[^a-z0-9]+", "-", s.translate(tr).lower()).strip("-")
    # Folder name is "<slug>_<stamp>"; cap the slug so it stays under the 255-byte filename limit.
    return (s[:120].rstrip("-") or "target")

def build_profile_text(profile, case):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    out = [f"# KARGU-OSINT target profile — case: {case}",
           f"# created: {ts} (built by kargu-new)",
           "# format: 'key: value', one value per line, a key may repeat.",
           ""]
    for f in FIELDS:
        for v in profile.get(f["key"], []):
            out.append(f"{f['key']}: {v}")
    return "\n".join(out) + "\n"

def summary(profile, case, opts):
    print()
    print(CY("──────────────────────────────────────────────────────────"))
    print(CY(f"  SUMMARY · case \"{case}\""))
    print(CY("──────────────────────────────────────────────────────────"))
    empty = True
    for f in FIELDS:
        vals = profile.get(f["key"], [])
        if vals:
            empty = False
            print(f"  {f['title']:<24} {B(', '.join(vals))}")
        else:
            print(DIM(f"  {f['title']:<24} —"))
    print(DIM("  " + "-" * 54))
    print(f"  {'Derive usernames':<24} {'yes (max %d)' % opts['max_users'] if opts['derive'] else 'no'}")
    print(f"  {'Route through Tor':<24} {'yes' if opts['tor'] else 'no'}")
    print(f"  {'SpiderFoot deep scan':<24} {'yes' if opts['deep'] else 'no'}")
    print(f"  {'API sources':<24} {'enabled' if opts['api'] else 'disabled'}")
    print(f"  {'Correlation depth':<24} {opts['depth']}")
    print(f"  {'Local face matching':<24} {'yes' if opts.get('faces') else 'no'}")
    print(f"  {'DeepFace confirmer':<24} {'yes' if opts.get('deepface') else 'no'}")
    print(f"  {'CLIP similarity':<24} {'yes' if opts.get('clip') else 'no'}")
    print(CY("──────────────────────────────────────────────────────────"))
    return empty

def main():
    ap = argparse.ArgumentParser(description="KARGU-OSINT interactive target intake")
    ap.add_argument("--name", help="case name (used for the target/report file names)")
    ap.add_argument("--no-run", action="store_true", help="only write the target file, do not scan")
    args = ap.parse_args()

    print()
    print(CY("╔══════════════════════════════════════════════════════════╗"))
    print(CY("║   KARGU-OSINT · TARGET INTAKE                            ║"))
    print(CY("║   Answer what you know. Anything unknown can be skipped. ║"))
    print(CY("╚══════════════════════════════════════════════════════════╝"))
    print(DIM("  Only run this against targets you are authorised to investigate"))
    print(DIM("  (your own accounts, or an engagement you have permission for)."))

    profile = {}
    total = len(FIELDS)
    for i, f in enumerate(FIELDS, 1):
        profile[f["key"]] = ask_field(f, i, total)

    if not any(profile[k["key"]] for k in FIELDS if k["key"] != "notes"):
        print(RD("\nNothing to scan — every field was skipped. Exiting."))
        sys.exit(1)

    case = args.name
    if not case:
        print()
        print(CY("[case] Name for this investigation"))
        print(DIM("      Used for the target file and the report file names."))
        default = slugify(profile["name"][0]) if profile["name"] else (
                  slugify(profile["username"][0]) if profile["username"] else "target")
        print(DIM(f"      Press Enter to use: {default}"))
        try:
            case = input(B("      > ")).strip() or default
        except (EOFError, KeyboardInterrupt):
            print("\n" + YL("Cancelled.")); sys.exit(130)
    case = slugify(case)

    print()
    print(CY("[options] Scan behaviour"))
    opts = {}
    opts["derive"]    = ask_yes("Derive extra candidate usernames from the name/e-mail?", True)
    opts["max_users"] = 3
    if opts["derive"]:
        try:
            r = input(B("      How many candidates at most? [3] ")).strip()
            opts["max_users"] = max(1, int(r)) if r else 3
        except (ValueError, EOFError, KeyboardInterrupt):
            opts["max_users"] = 3
    opts["api"]   = ask_yes("Use API sources (numverify / VirusTotal / Chaos / Hunter)?", True)
    opts["tor"]   = ask_yes("Route the tools through Tor (proxychains)?", False)
    opts["deep"]  = ask_yes("Run the SpiderFoot deep scan (slow)?", False)
    opts["depth"] = 1
    opts["faces"] = opts["deepface"] = opts["clip"] = False
    if ML_PY.exists():
        print(DIM("      Local vision stack found (ml/.venv). Face matching is biometric processing:"))
        print(DIM("      use it only with a lawful basis for this target."))
        opts["faces"] = ask_yes("Compare faces across the pictures found (local, --faces)?", False)
        if opts["faces"]:
            print(DIM("      DeepFace re-checks each match and stamps the ones it cannot confirm."))
            opts["deepface"] = ask_yes("Re-check the matches with DeepFace (slower, --deepface)?", False)
        opts["clip"]  = ask_yes("CLIP visual similarity for reference photos (local, --clip)?", False)
    elif profile.get("image"):
        print(DIM("      Face matching needs the local vision stack: dashboard/install-ml.sh"))

    if summary(profile, case, opts):
        print(RD("Nothing to scan.")); sys.exit(1)

    if not ask_yes("Save this profile and start the scan?", True):
        print(YL("Aborted — nothing was written."))
        sys.exit(0)

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = CASES / f"{case}_{stamp}"
    folder.mkdir(parents=True, exist_ok=True)
    tfile = folder / f"{case}.txt"
    tfile.write_text(build_profile_text(profile, case), encoding="utf-8")
    print(GN(f"\n  Case folder : {folder}"))
    print(GN(f"  Profile     : {tfile.name}"))
    print(DIM(f"  The report ({case}.html) will land in the same folder."))

    if args.no_run:
        print(DIM(f"  Run it later with:  kargu {tfile}"))
        return

    cmd = [sys.executable, str(OSINT / "osint_run.py"), str(tfile), "--depth", str(opts["depth"])]
    if not opts["derive"]: cmd.append("--no-derive")
    else:                  cmd += ["--max-users", str(opts["max_users"])]
    if opts["tor"]:  cmd.append("--tor")
    if opts["deep"]: cmd.append("--deep")
    if not opts["api"]: cmd.append("--no-api")
    if opts.get("faces"):    cmd.append("--faces")
    if opts.get("deepface"): cmd.append("--deepface")
    if opts.get("clip"):     cmd.append("--clip")

    env = dict(os.environ)
    env["PATH"] = f"{OSINT/'bin'}:{env.get('PATH','')}"
    print(DIM(f"  Running: {' '.join(cmd)}\n"))
    try:
        rc = subprocess.call(cmd, env=env)
    except KeyboardInterrupt:
        print(YL("\nScan interrupted.")); rc = 130
    sys.exit(rc)

if __name__ == "__main__":
    main()
