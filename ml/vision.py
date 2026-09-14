#!/usr/bin/env python3
"""Local vision helper for KARGU-OSINT: tiered face matching & CLIP similarity.

The stages run in one order, each narrowing what the next has to look at:
  1. hash          — the scanner's own dHash/pHash pass, before this script runs
  2. InsightFace   — ArcFace/buffalo_l embeddings, decides which pictures match
  3. DeepFace      — Facenet512 + VGG-Face, re-checks ONLY what InsightFace matched
  4. CLIP          — ViT-B-32, semantic similarity, independent of the face stages

DeepFace is a confirmer, never a proposer: it cannot create a match, only agree or refuse.
A refusal is reported as "disputed" and the caller stamps the picture, because on this
project's input (small avatars, logos, letter avatars) DeepFace scoring pictures on its own
produced verified matches between unrelated logos.

Runs in ml/.venv (Python 3.12); the scanner and the dashboard call it as a subprocess.
Face embeddings are special-category biometric data (KVKK art. 6 / GDPR art. 9):
callers gate them behind an explicit opt-in (--faces / --deepface).

    vision.py analyze <case.json | -> [--faces] [--deepface] [--clip] [--threshold 0.5] [--base DIR]
    vision.py clip    <case.json> --query "text"
    vision.py warmup                      # download the models once (needs network)
"""
import argparse
import base64
import io
import json
import os
import sys
import tempfile
from pathlib import Path

MODELS = Path(__file__).resolve().parent / "models"
FACE_MODEL = "buffalo_l"
CLIP_MODEL = ("ViT-B-32", "laion2b_s34b_b79k")
FACE_STRONG = 0.65          # ArcFace cosine above this is a confident same-person call
CLIP_SIMILAR = 0.85         # CLIP image-image cosine above this reads as "same scene/subject"
DET_MIN_SIDE = 320          # small avatars are upscaled before detection

DEEPFACE_MODELS = ["Facenet512", "VGG-Face"]
DEEPFACE_DETECTOR = "retinaface"
DEEPFACE_METRIC = "cosine"

os.environ.setdefault("HF_HUB_CACHE", str(MODELS))
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
# DeepFace logs to stdout, and stdout here carries the single JSON document the callers parse.
os.environ.setdefault("DEEPFACE_LOG_LEVEL", "50")


def _decode(uri):
    from PIL import Image
    raw = base64.b64decode(uri.split(",", 1)[1])
    return Image.open(io.BytesIO(raw)).convert("RGB")


def _open(path):
    from PIL import Image
    return Image.open(path).convert("RGB")


def _first_image(cands):
    """First loadable source in preference order: (kind, value) with kind file|uri."""
    for kind, val in cands:
        if not val:
            continue
        try:
            if kind == "file":
                p = Path(val)
                if p.is_file():
                    return _open(p)
            elif val.startswith("data:image"):
                return _decode(val)
        except Exception:
            continue
    return None


def _owner(acc):
    """Two pictures with the same owner are never evidence of anything."""
    from urllib.parse import urlsplit
    host = (urlsplit(acc.get("url") or "").hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    return host or (acc.get("site") or "?").lower()


def collect_images(case, base=None):
    """Every picture in a case export as {key, label, owner, image, kind}.

    Full-size files under the case folder (avatar_file / hd_file / source) are preferred
    over the embedded thumbnails: a 72 px avatar rarely yields a usable face embedding."""
    base = Path(base) if base else None
    rel = (lambda p: str(base / p) if (base and p and not Path(p).is_absolute()) else p)
    out = []
    for i, ti in enumerate(case.get("target_images") or []):
        if ti.get("error"):
            continue
        im = _first_image([("file", rel(ti.get("hd_file"))), ("file", None if ti.get("is_url") else ti.get("source")),
                           ("uri", ti.get("thumb"))])
        if im is not None:
            out.append({"key": f"target:{i}", "label": f"reference {ti.get('filename') or i}",
                        "owner": f"target:{i}", "kind": "target", "image": im})
    for i, a in enumerate(case.get("accounts") or []):
        if a.get("state") not in (None, "verified"):
            continue
        if a.get("avatar_is_generated"):
            continue
        # avatar may carry a burnt-in "not confirmed" stamp from a previous run; avatar_plain
        # is the untouched copy the scanner keeps beside it.
        im = _first_image([("file", rel(a.get("avatar_file"))), ("uri", a.get("avatar_plain")),
                           ("uri", a.get("avatar"))])
        if im is not None:
            out.append({"key": f"acct:{i}", "label": f"{a.get('site') or '?'} @{a.get('user') or ''}".strip(),
                        "owner": _owner(a), "kind": "avatar", "image": im,
                        "site": a.get("site"), "user": a.get("user"), "url": a.get("url")})
        cov = a.get("cover_thumb_plain") or a.get("cover_thumb") or a.get("avatar_cover_uri")
        im = _first_image([("uri", cov)])
        if im is not None:
            out.append({"key": f"cover:{i}", "label": f"{a.get('site') or '?'} cover", "owner": _owner(a),
                        "kind": "cover", "image": im, "site": a.get("site"), "user": a.get("user"), "url": a.get("url")})
    for i, m in enumerate(case.get("metadata") or []):
        th = (m.get("meta") or {}).get("_thumbnail")
        im = _first_image([("uri", th)])
        if im is not None:
            name = (m.get("file") or "").split("/")[-1]
            out.append({"key": f"exif:{i}", "label": f"{name} (exif)", "owner": f"exif:{i}", "kind": "exif", "image": im})
    return out


def _upscaled(im):
    from PIL import Image
    w, h = im.size
    if min(w, h) >= DET_MIN_SIDE:
        return im
    s = DET_MIN_SIDE / min(w, h)
    return im.resize((int(w * s), int(h * s)), Image.Resampling.LANCZOS)


def face_embeddings(images):
    """[(key, normed_embedding)] — one entry per detected face."""
    import numpy as np
    from insightface.app import FaceAnalysis
    # insightface downloads a missing model pack on its own; a scan must never reach the network.
    if not (MODELS / "models" / FACE_MODEL).is_dir():
        raise RuntimeError("face model missing: run `ml/.venv/bin/python ml/vision.py warmup`")
    app = FaceAnalysis(name=FACE_MODEL, root=str(MODELS), providers=["CPUExecutionProvider"])
    app.prepare(ctx_id=-1, det_size=(640, 640))
    vecs = []
    for img in images:
        arr = np.array(_upscaled(img["image"]))[:, :, ::-1]      # RGB -> BGR
        faces = app.get(arr)
        img["faces"] = len(faces)
        for fc in faces:
            vecs.append((img["key"], fc.normed_embedding))
    return vecs


def deepface_home():
    """Where DeepFace keeps its weights; they are downloaded by warmup, never by a scan."""
    return Path(os.environ.get("DEEPFACE_HOME") or Path.home()) / ".deepface" / "weights"


def deepface_confirm(images, pairs, models=None, detector=None):
    """Second opinion on the pairs InsightFace already matched.

    Each picture is embedded once per model, not once per pair, so the cost is linear in
    pictures instead of quadratic. enforce_detection stays on: a picture with no detectable
    face abstains, rather than having its raw pixels scored as though they were a face.
    """
    models = models or DEEPFACE_MODELS
    detector = detector or DEEPFACE_DETECTOR
    import numpy as np
    from deepface import DeepFace
    from deepface.modules import verification as dfv

    by_key = {img["key"]: img for img in images}
    # One verdict per pair: face_embeddings emits an entry per detected face, so a picture
    # with two faces arrives several times under the same key.
    uniq, seen_pairs = [], set()
    for p in pairs:
        k = (p["a"], p["b"])
        if k not in seen_pairs:
            seen_pairs.add(k)
            uniq.append(p)
    keys = sorted({k for p in uniq for k in (p["a"], p["b"]) if k in by_key})

    emb = {m: {} for m in models}
    errors = {}
    for model in models:
        for k in keys:
            arr = np.array(_upscaled(by_key[k]["image"]))[:, :, ::-1]   # RGB -> BGR
            try:
                reps = DeepFace.represent(arr, model_name=model, detector_backend=detector,
                                          enforce_detection=True, align=True, max_faces=1)
            except ValueError as e:
                # only the detector's own refusal means "no face"; anything else is a broken model
                if "could not be detected" not in str(e).lower():
                    errors.setdefault(model, str(e)[:160])
                continue
            except Exception as e:
                errors.setdefault(model, f"{type(e).__name__}: {e}"[:160])
                continue
            if reps:
                emb[model][k] = reps[0]["embedding"]
    # A model that produced nothing at all is unusable, not shy. Reporting that as "no face"
    # would be a claim about the pictures that DeepFace never actually made.
    dead = [m for m in models if not emb[m]]
    if dead:
        raise RuntimeError("DeepFace model(s) unusable: "
                           + ", ".join(f"{m} ({errors.get(m, 'no output')})" for m in dead))

    out = []
    for p in uniq:
        multi = [k for k in (p["a"], p["b"]) if (by_key.get(k) or {}).get("faces", 1) > 1]
        rows = []
        for model in models:
            va, vb = emb[model].get(p["a"]), emb[model].get(p["b"])
            if va is None or vb is None:
                continue
            dist = float(dfv.find_cosine_distance(va, vb))
            thr = float(dfv.find_threshold(model, DEEPFACE_METRIC))
            rows.append({"model": model, "verified": bool(dist <= thr),
                         "distance": round(dist, 4), "threshold": round(thr, 4)})
        reason = ""
        if multi:
            # represent(max_faces=1) keeps the largest face, which need not be the one
            # InsightFace matched, so a verdict here could be about a different person.
            status = "abstained"
            reason = "more than one face in the picture: cannot tell which one InsightFace matched"
        elif not rows:
            status = "abstained"
            reason = "DeepFace found no usable face"
        elif all(r["verified"] for r in rows):
            status = "confirmed"
        else:
            status = "disputed"
        rec = {"a": p["a"], "b": p["b"], "insightface_score": p.get("score"),
               "status": status, "models": rows, "models_asked": len(models)}
        if reason:
            rec["reason"] = reason
        out.append(rec)
    order = {"disputed": 0, "abstained": 1, "confirmed": 2}
    out.sort(key=lambda m: (order.get(m["status"], 9), -(m.get("insightface_score") or 0)))
    return out


def clip_embeddings(images):
    import torch
    import open_clip
    model, _, preprocess = open_clip.create_model_and_transforms(
        CLIP_MODEL[0], pretrained=CLIP_MODEL[1], cache_dir=str(MODELS))
    with torch.no_grad():
        vec = torch.cat([model.encode_image(preprocess(img["image"]).unsqueeze(0)) for img in images])
        vec /= vec.norm(dim=-1, keepdim=True)
    return model, vec


def pair_matches(vecs, owners, threshold, dot):
    """Pairs of different-owner embeddings whose similarity reaches threshold, best first."""
    out = []
    for i in range(len(vecs)):
        for j in range(i + 1, len(vecs)):
            ka, kb = vecs[i][0], vecs[j][0]
            if owners.get(ka) == owners.get(kb):
                continue
            score = float(dot(vecs[i][1], vecs[j][1]))
            if score >= threshold:
                out.append({"a": ka, "b": kb, "score": round(score, 3)})
    out.sort(key=lambda m: -m["score"])
    return out


def _labelled(matches, by_key):
    for m in matches:
        for side in ("a", "b"):
            img = by_key.get(m[side], {})
            m[side + "_label"] = img.get("label", m[side])
            m[side + "_kind"] = img.get("kind", "")
    return matches


def analyze(case, faces=True, deepface=False, clip=False, threshold=0.5, base=None):
    images = collect_images(case, base)
    by_key = {img["key"]: img for img in images}
    owners = {img["key"]: img["owner"] for img in images}
    res = {"engine": {}, "threshold": threshold, "images": [], "face_matches": [],
           "deepface_confirms": [], "clip_similar": [],
           "faces_total": 0, "ran": {"faces": False, "deepface": False, "clip": False}}
    if not images:
        res["note"] = "no pictures in this case"
        return res
    if faces:
        import numpy as np
        vecs = face_embeddings(images)
        res["engine"]["faces"] = f"insightface/{FACE_MODEL} (CPU)"
        res["faces_total"] = len(vecs)
        res["face_matches"] = _labelled(pair_matches(vecs, owners, threshold, np.dot), by_key)
        res["ran"]["faces"] = True
    if deepface:
        if not res["ran"]["faces"]:
            res["deepface_error"] = "DeepFace is a confirmer; it needs the InsightFace stage (--faces)"
        elif not deepface_home().is_dir():
            res["deepface_error"] = "DeepFace weights missing: run `ml/vision.py warmup`"
        else:
            try:
                res["deepface_confirms"] = _labelled(
                    deepface_confirm(images, res["face_matches"]), by_key)
                res["engine"]["deepface"] = (f"deepface/{'+'.join(DEEPFACE_MODELS)} "
                                             f"detector={DEEPFACE_DETECTOR} (CPU, confirmer)")
                res["ran"]["deepface"] = True
            except Exception as e:
                res["deepface_error"] = f"{type(e).__name__}: {e}"
    if clip:
        _, vec = clip_embeddings(images)
        res["engine"]["clip"] = f"open_clip/{CLIP_MODEL[0]}:{CLIP_MODEL[1]} (CPU)"
        # Only reference-vs-captured pairs: similarity between two captured pictures is
        # already covered by the hash-based grouping in the scanner.
        tv = [(img["key"], vec[i]) for i, img in enumerate(images) if img["kind"] == "target"]
        ov = [(img["key"], vec[i]) for i, img in enumerate(images) if img["kind"] != "target"]
        pairs = []
        for ka, va in tv:
            for kb, vb in ov:
                s = float((va * vb).sum())
                if s >= CLIP_SIMILAR:
                    pairs.append({"a": ka, "b": kb, "score": round(s, 3)})
        pairs.sort(key=lambda m: -m["score"])
        res["clip_similar"] = _labelled(pairs, by_key)
        res["ran"]["clip"] = True
    res["images"] = [{k: img.get(k) for k in ("key", "label", "owner", "kind", "faces", "site", "user", "url")
                      if img.get(k) is not None} for img in images]
    return res


def clip_search(case, query, base=None):
    import torch
    import open_clip
    images = collect_images(case, base)
    if not images:
        return {"query": query, "results": []}
    model, ivec = clip_embeddings(images)
    tok = open_clip.get_tokenizer(CLIP_MODEL[0])
    with torch.no_grad():
        tvec = model.encode_text(tok([query]))
        tvec /= tvec.norm(dim=-1, keepdim=True)
        sims = (ivec @ tvec.T).squeeze(1).tolist()
    res = sorted(({"key": images[i]["key"], "label": images[i]["label"], "score": round(float(s), 3)}
                  for i, s in enumerate(sims)), key=lambda x: -x["score"])
    return {"query": query, "results": res}


def warmup():
    os.environ.pop("HF_HUB_OFFLINE", None)
    loaded = []
    # InsightFace
    from insightface.app import FaceAnalysis
    FaceAnalysis(name=FACE_MODEL, root=str(MODELS), providers=["CPUExecutionProvider"]).prepare(ctx_id=-1)
    loaded.append(f"insightface/{FACE_MODEL}")
    # CLIP
    import open_clip
    open_clip.create_model_and_transforms(CLIP_MODEL[0], pretrained=CLIP_MODEL[1], cache_dir=str(MODELS))
    loaded.append(f"open_clip/{CLIP_MODEL[0]}")
    # DeepFace (optional confirmer): its weights live under DEEPFACE_HOME, not ml/models.
    try:
        from deepface import DeepFace
        for m in DEEPFACE_MODELS:
            DeepFace.build_model(m)
            loaded.append(f"deepface/{m}")
        DeepFace.build_model(DEEPFACE_DETECTOR, task="face_detector")
        loaded.append(f"deepface/{DEEPFACE_DETECTOR}")
    except Exception as e:
        loaded.append(f"deepface/not installed ({type(e).__name__})")
    return {"ok": True, "models": str(MODELS), "loaded": loaded}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["analyze", "faces", "clip", "warmup"])
    ap.add_argument("case", nargs="?", help="case .json, or - for stdin")
    ap.add_argument("--faces", action="store_true")
    ap.add_argument("--deepface", action="store_true",
                    help="re-check the InsightFace matches with DeepFace (confirmer, needs --faces)")
    ap.add_argument("--clip", action="store_true")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--query", default="")
    ap.add_argument("--base", default=None, help="folder that relative image paths resolve against")
    a = ap.parse_args()
    if a.mode == "warmup":
        try:
            out = warmup()
        except Exception as e:
            out = {"error": f"{type(e).__name__}: {e}"}
        json.dump(out, sys.stdout)
        return
    # Models are cached by warmup/first use; later runs must never phone home.
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    if not a.case:
        ap.error("case is required")
    try:
        text = sys.stdin.read() if a.case == "-" else Path(a.case).read_text(encoding="utf-8")
        case = json.loads(text)
        base = a.base or (None if a.case == "-" else str(Path(a.case).resolve().parent))
        if a.mode == "clip":
            out = clip_search(case, a.query, base)
        elif a.mode == "faces":
            out = analyze(case, faces=True, deepface=a.deepface, clip=False, threshold=a.threshold, base=base)
        else:
            # --deepface implies the InsightFace stage it confirms.
            run_faces = a.faces or a.deepface or not a.clip
            out = analyze(case, faces=run_faces, deepface=a.deepface, clip=a.clip,
                          threshold=a.threshold, base=base)
    except Exception as e:
        out = {"error": f"{type(e).__name__}: {e}"}
    json.dump(out, sys.stdout, ensure_ascii=False)


if __name__ == "__main__":
    main()
