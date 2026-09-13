#!/usr/bin/env python3
"""Local vision helper for KARGU-OSINT: face matching (InsightFace) and CLIP similarity/search.

Runs in ml/.venv (Python 3.12); the scanner and the dashboard call it as a subprocess.
Everything happens on the local CPU and nothing is uploaded. Face embeddings are
special-category biometric data (KVKK art. 6 / GDPR art. 9): callers gate them behind
an explicit opt-in (--faces).

    vision.py analyze <case.json | -> [--faces] [--clip] [--threshold 0.5] [--base DIR]
    vision.py clip    <case.json> --query "text"
    vision.py warmup                      # download the models once (needs network)

"analyze" reads the case export (or stdin with "-"), gathers every picture it holds and
returns JSON: per-image face counts, cross-owner face matches and CLIP image-image
similarity between operator reference images and captured pictures.
"""
import argparse
import base64
import io
import json
import os
import sys
from pathlib import Path

MODELS = Path(__file__).resolve().parent / "models"
FACE_MODEL = "buffalo_l"
CLIP_MODEL = ("ViT-B-32", "laion2b_s34b_b79k")
FACE_STRONG = 0.65          # ArcFace cosine above this is a confident same-person call
CLIP_SIMILAR = 0.85         # CLIP image-image cosine above this reads as "same scene/subject"
DET_MIN_SIDE = 320          # small avatars are upscaled before detection

os.environ.setdefault("HF_HUB_CACHE", str(MODELS))


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
        im = _first_image([("file", rel(a.get("avatar_file"))), ("uri", a.get("avatar"))])
        if im is not None:
            out.append({"key": f"acct:{i}", "label": f"{a.get('site') or '?'} @{a.get('user') or ''}".strip(),
                        "owner": _owner(a), "kind": "avatar", "image": im,
                        "site": a.get("site"), "user": a.get("user"), "url": a.get("url")})
        cov = a.get("cover_thumb") or a.get("avatar_cover_uri")
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


def analyze(case, faces=True, clip=False, threshold=0.5, base=None):
    images = collect_images(case, base)
    by_key = {img["key"]: img for img in images}
    owners = {img["key"]: img["owner"] for img in images}
    res = {"engine": {}, "threshold": threshold, "images": [], "face_matches": [], "clip_similar": [],
           "faces_total": 0, "ran": {"faces": False, "clip": False}}
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
    from insightface.app import FaceAnalysis
    FaceAnalysis(name=FACE_MODEL, root=str(MODELS), providers=["CPUExecutionProvider"]).prepare(ctx_id=-1)
    import open_clip
    open_clip.create_model_and_transforms(CLIP_MODEL[0], pretrained=CLIP_MODEL[1], cache_dir=str(MODELS))
    return {"ok": True, "models": str(MODELS)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["analyze", "faces", "clip", "warmup"])
    ap.add_argument("case", nargs="?", help="case .json, or - for stdin")
    ap.add_argument("--faces", action="store_true")
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
            out = analyze(case, faces=True, clip=False, threshold=a.threshold, base=base)
        else:
            out = analyze(case, faces=a.faces or not a.clip, clip=a.clip, threshold=a.threshold, base=base)
    except Exception as e:
        out = {"error": f"{type(e).__name__}: {e}"}
    json.dump(out, sys.stdout, ensure_ascii=False)


if __name__ == "__main__":
    main()
