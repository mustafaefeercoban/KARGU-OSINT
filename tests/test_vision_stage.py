#!/usr/bin/env python3
"""Offline tests for the local vision stage: merge rules, HD copies, report/AUTO-FINDINGS output."""
import base64
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest

from PIL import Image

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import osint_run as O  # noqa: E402


def _load_vision():
    spec = importlib.util.spec_from_file_location("vision", ROOT / "ml" / "vision.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


V = _load_vision()


def _accounts():
    return [{"site": "GitHub", "user": "pa", "url": "https://github.com/pa", "state": "verified",
             "avatar": "data:image/jpeg;base64,x", "avatar_hash": "00ff"},
            {"site": "GitLab", "user": "pa", "url": "https://gitlab.com/pa", "state": "verified", "avatar_hash": "00ff"},
            {"site": "Chess", "user": "pb", "url": "https://chess.com/member/pb", "state": "verified"}]


def _result():
    return {"status": "ran", "ran": {"faces": True, "clip": True}, "threshold": 0.5, "faces_total": 4, "images": [],
            "face_matches": [{"a": "target:0", "b": "acct:0", "score": 0.965},
                             {"a": "acct:0", "b": "acct:1", "score": 0.732},
                             {"a": "target:0", "b": "acct:1", "score": 0.72}],
            "clip_similar": [{"a": "target:0", "b": "acct:0", "score": 0.872},
                             {"a": "target:0", "b": "acct:2", "score": 0.86}]}


class MergeVision(unittest.TestCase):

    def test_face_and_clip_pairs_land_on_the_reference_image(self):
        """A face pair becomes a 'face' match; a hash match on the same account only gains the score."""
        accs = _accounts()
        ti = {"filename": "ref.jpg", "matches": [{"site": "GitLab", "user": "pa", "url": "https://gitlab.com/pa",
                                                  "tier": "possible", "kind": "avatar"}]}
        f = {"target_images": [ti], "verified": accs}
        O.merge_vision(f, _result(), accs)
        by_site = {m["site"]: m for m in ti["matches"]}
        self.assertEqual(by_site["GitHub"]["tier"], "face")
        self.assertEqual(by_site["GitHub"]["clip_score"], 0.872)
        self.assertEqual(by_site["GitLab"]["tier"], "face")          # upgraded from possible
        self.assertEqual(by_site["GitLab"]["face_score"], 0.72)
        self.assertEqual(by_site["Chess"]["tier"], "similar")
        self.assertEqual([m["site"] for m in ti["matches"]], ["GitHub", "GitLab", "Chess"])
        self.assertEqual(accs[0]["face_match"], 0.965)
        self.assertIsNone(accs[2].get("face_match"))

    def test_account_pairs_form_face_groups_across_hosts(self):
        accs = _accounts()
        f = {"target_images": [], "verified": accs}
        O.merge_vision(f, _result(), accs)
        self.assertEqual(len(f["face_groups"]), 1)
        g = f["face_groups"][0]
        self.assertEqual([m["site"] for m in g["members"]], ["GitHub", "GitLab"])
        self.assertEqual((g["min_score"], g["max_score"]), (0.732, 0.732))
        self.assertEqual((accs[0]["face_group"], accs[1]["face_group"], accs[2].get("face_group")), (1, 1, None))

    def test_same_host_pairs_are_not_a_group(self):
        accs = [{"site": "X", "user": "a", "url": "https://x.com/a", "state": "verified"},
                {"site": "X", "user": "b", "url": "https://x.com/b", "state": "verified"}]
        f = {"target_images": [], "verified": accs}
        O.merge_vision(f, {"status": "ran", "face_matches": [{"a": "acct:0", "b": "acct:1", "score": 0.9}]}, accs)
        self.assertEqual(f["face_groups"], [])

    def test_several_faces_in_one_picture_keep_the_best_score(self):
        accs = _accounts()
        ti = {"filename": "ref.jpg", "matches": [{"site": "GitHub", "url": "https://github.com/pa", "tier": "strong", "kind": "avatar"}]}
        f = {"target_images": [ti], "verified": accs}
        res = {"status": "ran", "face_matches": [{"a": "target:0", "b": "acct:0", "score": 0.91},
                                                 {"a": "target:0", "b": "acct:0", "score": 0.52}]}
        O.merge_vision(f, res, accs)
        self.assertEqual(ti["matches"][0]["face_score"], 0.91)
        self.assertEqual(ti["matches"][0]["tier"], "strong")
        self.assertEqual(accs[0]["face_match"], 0.91)

    def test_skipped_result_changes_nothing(self):
        accs = _accounts()
        f = {"target_images": [{"filename": "r", "matches": []}], "verified": accs}
        O.merge_vision(f, {"status": "skipped", "reason": "x"}, accs)
        self.assertEqual(f["target_images"][0]["matches"], [])
        self.assertNotIn("face_groups", f)


class StageVision(unittest.TestCase):

    def test_deepface_is_dropped_when_its_weights_were_never_downloaded(self):
        old_py, old_osint, old_w = O.ML_PY, O.OSINT, O.DEEPFACE_WEIGHTS
        try:
            with tempfile.TemporaryDirectory() as td:
                O.ML_PY = ROOT / "osint_run.py"
                O.OSINT = ROOT                       # buffalo_l is present, so faces would run
                O.DEEPFACE_WEIGHTS = pathlib.Path(td) / "nope"
                f = {}
                O.stage_vision(f, [], faces=True, deepface=True)
                self.assertIn("warmup", f["deepface_note"])
        finally:
            O.ML_PY, O.OSINT, O.DEEPFACE_WEIGHTS = old_py, old_osint, old_w

    def test_not_requested_and_missing_venv(self):
        self.assertEqual(O.stage_vision({}, [], faces=False, clip=False)["status"], "skipped")
        old = O.ML_PY
        try:
            O.ML_PY = pathlib.Path("/nonexistent/python")
            r = O.stage_vision({}, [], faces=True)
            self.assertEqual(r["status"], "skipped")
            self.assertIn("install-ml.sh", r["reason"])
        finally:
            O.ML_PY = old


def _confirms():
    return [{"a": "target:0", "b": "acct:0", "status": "confirmed", "insightface_score": 0.966,
             "models": [{"model": "Facenet512", "verified": True, "distance": 0.068, "threshold": 0.3},
                        {"model": "VGG-Face", "verified": True, "distance": 0.057, "threshold": 0.68}]},
            {"a": "target:0", "b": "acct:1", "status": "disputed", "insightface_score": 0.722,
             "models": [{"model": "Facenet512", "verified": False, "distance": 0.3546, "threshold": 0.3},
                        {"model": "VGG-Face", "verified": True, "distance": 0.3886, "threshold": 0.68}]},
            {"a": "acct:1", "b": "acct:2", "status": "abstained", "insightface_score": 0.51, "models": []}]


class DeepFaceConfirmer(unittest.TestCase):

    @staticmethod
    def _jpeg_uri():
        buf = io.BytesIO()
        Image.new("RGB", (72, 72), (30, 90, 160)).save(buf, "JPEG")
        return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()

    def _case(self):
        accs = _accounts()
        for a in accs:
            a["avatar"] = self._jpeg_uri()
        ti = {"filename": "ref.jpg", "matches": [], "thumb": self._jpeg_uri()}
        f = {"target_images": [ti], "verified": accs}
        res = {"status": "ran", "ran": {"faces": True, "deepface": True},
               "face_matches": [{"a": "target:0", "b": "acct:0", "score": 0.966},
                                {"a": "target:0", "b": "acct:1", "score": 0.722},
                                {"a": "acct:1", "b": "acct:2", "score": 0.51}],
               "deepface_confirms": _confirms()}
        return f, ti, accs, res

    def test_verdicts_land_on_accounts_and_on_the_reference_match(self):
        """A confirmer verdict annotates the InsightFace pair; it never creates one."""
        f, ti, accs, res = self._case()
        before = len(res["face_matches"])
        O.merge_vision(f, res, accs)
        self.assertEqual(accs[0]["deepface_status"], "confirmed")
        self.assertEqual(accs[1]["deepface_status"], "disputed")
        by_site = {m["site"]: m for m in ti["matches"]}
        self.assertEqual(by_site["GitHub"]["deepface_status"], "confirmed")
        self.assertEqual(by_site["GitLab"]["deepface_status"], "disputed")
        self.assertEqual(len(ti["matches"]), before - 1)   # the acct/acct pair is not a reference match

    def test_only_the_disputed_picture_is_stamped(self):
        f, ti, accs, res = self._case()
        plain = {a["site"]: a["avatar"] for a in accs}
        O.merge_vision(f, res, accs)
        self.assertEqual(accs[0]["avatar"], plain["GitHub"])      # confirmed, untouched
        self.assertTrue(accs[1].get("deepface_marked"))
        self.assertNotEqual(accs[1]["avatar"], plain["GitLab"])   # disputed, stamped

    def test_one_confirmation_anywhere_saves_a_picture_from_the_stamp(self):
        """A photo DeepFace vouched for in some pair is not stamped because another pair failed."""
        accs = _accounts()
        for a in accs:
            a["avatar"] = self._jpeg_uri()
        plain = accs[1]["avatar"]
        f = {"target_images": [], "verified": accs}
        res = {"status": "ran", "ran": {"deepface": True}, "face_matches": [],
               "deepface_confirms": [
                   {"a": "acct:0", "b": "acct:1", "status": "confirmed", "models": []},
                   {"a": "acct:1", "b": "acct:2", "status": "disputed", "models": []}]}
        O.merge_vision(f, res, accs)
        self.assertEqual(accs[1]["deepface_status"], "confirmed")
        self.assertEqual(accs[1]["avatar"], plain)
        self.assertEqual(accs[2]["deepface_status"], "disputed")
        self.assertTrue(accs[2]["deepface_marked"])

    def test_a_cluster_reports_how_many_of_its_links_deepface_refused(self):
        accs = _accounts()
        f = {"target_images": [], "verified": accs}
        res = {"status": "ran", "ran": {"faces": True, "deepface": True},
               "face_matches": [{"a": "acct:0", "b": "acct:1", "score": 0.73}],
               "deepface_confirms": [{"a": "acct:0", "b": "acct:1", "status": "disputed", "models": []}]}
        O.merge_vision(f, res, accs)
        self.assertEqual(f["face_groups"][0]["deepface_disputed"], 1)

    def test_no_confirms_leaves_every_account_unannotated(self):
        f, ti, accs, res = self._case()
        res["deepface_confirms"] = []
        O.merge_vision(f, res, accs)
        self.assertFalse(any(a.get("deepface_status") for a in accs))


class ConfirmerVerdicts(unittest.TestCase):
    """deepface_confirm's decision logic, with the models stubbed out."""

    def _run(self, pairs, images, embeddings, raises=None):
        """embeddings: {model: {key: vector}}; raises: {model: Exception} for every represent call."""
        import types
        fake_df = types.SimpleNamespace()

        def represent(arr, model_name=None, **kw):
            if raises and model_name in raises:
                raise raises[model_name]
            key = represent.current
            vec = embeddings.get(model_name, {}).get(key)
            if vec is None:
                raise ValueError("Face could not be detected in the image")
            return [{"embedding": vec}]
        represent.current = None
        fake_df.represent = represent

        class _Verification:
            @staticmethod
            def find_cosine_distance(a, b):
                return abs(a[0] - b[0])

            @staticmethod
            def find_threshold(model, metric):
                return 0.3

        class _Arr:                       # only has to survive np.array(im)[:, :, ::-1]
            def __getitem__(self, idx):
                return self

        mods = {"deepface": types.SimpleNamespace(DeepFace=fake_df),
                "deepface.modules": types.SimpleNamespace(verification=_Verification),
                "deepface.modules.verification": _Verification,
                "numpy": types.SimpleNamespace(array=lambda x: _Arr())}
        saved = {k: sys.modules.get(k) for k in mods}
        sys.modules.update(mods)
        # represent() needs to know which picture it was handed; patch _upscaled to record it
        orig_up = V._upscaled
        order = [img["key"] for img in images]

        def up(im):
            represent.current = order[up.i % len(order)]
            up.i += 1
            return im
        up.i = 0
        V._upscaled = up
        try:
            return V.deepface_confirm(images, pairs, models=["M1", "M2"], detector="stub")
        finally:
            V._upscaled = orig_up
            for k, v in saved.items():
                if v is None: sys.modules.pop(k, None)
                else: sys.modules[k] = v

    def _img(self, key, faces=1):
        return {"key": key, "label": key, "owner": key, "kind": "avatar",
                "image": Image.new("RGB", (80, 80)), "faces": faces}

    def test_duplicate_pairs_from_a_multi_face_picture_yield_one_verdict(self):
        imgs = [self._img("target:0"), self._img("acct:0")]
        pairs = [{"a": "target:0", "b": "acct:0", "score": 0.9},
                 {"a": "target:0", "b": "acct:0", "score": 0.6}]
        emb = {"M1": {"target:0": [0.0], "acct:0": [0.1]}, "M2": {"target:0": [0.0], "acct:0": [0.1]}}
        out = self._run(pairs, imgs, emb)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["status"], "confirmed")
        self.assertEqual(out[0]["models_asked"], 2)

    def test_a_picture_with_several_faces_abstains_instead_of_guessing(self):
        """represent(max_faces=1) keeps the largest face, which need not be the matched one."""
        imgs = [self._img("target:0"), self._img("acct:0", faces=2)]
        pairs = [{"a": "target:0", "b": "acct:0", "score": 0.9}]
        emb = {"M1": {"target:0": [0.0], "acct:0": [0.9]}, "M2": {"target:0": [0.0], "acct:0": [0.9]}}
        out = self._run(pairs, imgs, emb)
        self.assertEqual(out[0]["status"], "abstained")
        self.assertIn("more than one face", out[0]["reason"])

    def test_a_model_that_cannot_load_fails_loudly_instead_of_claiming_no_face(self):
        imgs = [self._img("target:0"), self._img("acct:0")]
        pairs = [{"a": "target:0", "b": "acct:0", "score": 0.9}]
        emb = {"M1": {"target:0": [0.0], "acct:0": [0.1]}, "M2": {}}
        with self.assertRaises(RuntimeError) as cm:
            self._run(pairs, imgs, emb, raises={"M2": ValueError("Exception while downloading weights")})
        self.assertIn("M2", str(cm.exception))

    def test_a_genuine_detection_refusal_abstains(self):
        imgs = [self._img("target:0"), self._img("acct:0")]
        pairs = [{"a": "target:0", "b": "acct:0", "score": 0.9}]
        emb = {"M1": {"target:0": [0.0]}, "M2": {"target:0": [0.0]}}   # acct:0 has no face anywhere
        out = self._run(pairs, imgs, emb)
        self.assertEqual(out[0]["status"], "abstained")
        self.assertIn("no usable face", out[0]["reason"])

    def test_one_model_refusing_makes_the_pair_disputed(self):
        imgs = [self._img("target:0"), self._img("acct:0")]
        pairs = [{"a": "target:0", "b": "acct:0", "score": 0.9}]
        emb = {"M1": {"target:0": [0.0], "acct:0": [0.1]},     # distance 0.1 <= 0.3 -> agrees
               "M2": {"target:0": [0.0], "acct:0": [0.9]}}     # distance 0.9 >  0.3 -> refuses
        out = self._run(pairs, imgs, emb)
        self.assertEqual(out[0]["status"], "disputed")
        self.assertEqual([r["verified"] for r in out[0]["models"]], [True, False])


class CoverVerdicts(unittest.TestCase):
    """acct:<i> and cover:<i> are the same account row but different photographs."""

    def _acct_with_cover(self):
        buf = io.BytesIO(); Image.new("RGB", (72, 72), (20, 90, 160)).save(buf, "JPEG")
        uri = "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()
        buf2 = io.BytesIO(); Image.new("RGB", (240, 120), (160, 90, 20)).save(buf2, "JPEG")
        cov = "data:image/jpeg;base64," + base64.b64encode(buf2.getvalue()).decode()
        return [{"site": "GitHub", "url": "https://github.com/a", "user": "a", "state": "verified",
                 "avatar": uri, "cover_thumb": cov}], uri, cov

    def test_a_refused_banner_does_not_stamp_the_profile_picture(self):
        accs, uri, cov = self._acct_with_cover()
        f = {"target_images": [], "verified": accs}
        O.merge_vision(f, {"status": "ran", "face_matches": [],
                           "deepface_confirms": [{"a": "target:0", "b": "cover:0",
                                                  "status": "disputed", "models": []}]}, accs)
        self.assertEqual(accs[0]["avatar"], uri)
        self.assertIsNone(accs[0].get("deepface_status"))
        self.assertEqual(accs[0]["cover_deepface_status"], "disputed")
        self.assertNotEqual(accs[0]["cover_thumb"], cov)
        self.assertEqual(accs[0]["cover_thumb_plain"], cov)

    def test_a_confirmed_banner_does_not_clear_a_refused_avatar(self):
        accs, uri, cov = self._acct_with_cover()
        f = {"target_images": [], "verified": accs}
        O.merge_vision(f, {"status": "ran", "face_matches": [],
                           "deepface_confirms": [
                               {"a": "target:0", "b": "acct:0", "status": "disputed", "models": []},
                               {"a": "target:0", "b": "cover:0", "status": "confirmed", "models": []}]}, accs)
        self.assertEqual(accs[0]["deepface_status"], "disputed")
        self.assertTrue(accs[0]["deepface_marked"])
        self.assertEqual(accs[0]["avatar_plain"], uri)

    def test_a_cover_verdict_never_labels_a_reference_match_row(self):
        accs, uri, cov = self._acct_with_cover()
        ti = {"filename": "r.jpg", "matches": [{"site": "GitHub", "url": "https://github.com/a"}]}
        f = {"target_images": [ti], "verified": accs}
        O.merge_vision(f, {"status": "ran", "face_matches": [],
                           "deepface_confirms": [{"a": "target:0", "b": "cover:0",
                                                  "status": "confirmed", "models": []}]}, accs)
        self.assertIsNone(ti["matches"][0].get("deepface_status"))


class Watermark(unittest.TestCase):

    def _uri(self, size=(72, 72)):
        buf = io.BytesIO()
        Image.new("RGB", size, (30, 90, 160)).save(buf, "JPEG")
        return "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()

    def test_a_small_thumbnail_is_enlarged_and_changed(self):
        """The stamp must stay legible, so a 72px avatar is scaled up before it is written."""
        src = self._uri()
        out = O._watermark(src)
        self.assertTrue(out.startswith("data:image/jpeg;base64,"))
        self.assertNotEqual(out, src)
        im = Image.open(io.BytesIO(base64.b64decode(out.split(",", 1)[1])))
        self.assertGreaterEqual(im.width, 220)
        self.assertEqual(im.width, im.height)              # a square avatar stays square

    def test_a_wide_picture_keeps_its_aspect_ratio(self):
        im = Image.open(io.BytesIO(base64.b64decode(
            O._watermark(self._uri((240, 120))).split(",", 1)[1])))
        self.assertAlmostEqual(im.width / im.height, 2.0, places=1)

    def test_anything_unreadable_comes_back_untouched(self):
        for bad in ("", None, "https://example.com/a.jpg", "data:image/jpeg;base64,not-base64"):
            self.assertEqual(O._watermark(bad), bad)


class StageVisionModelGuard(unittest.TestCase):

    def test_faces_without_the_model_pack_is_skipped_not_downloaded(self):
        old_py, old_osint = O.ML_PY, O.OSINT
        try:
            with tempfile.TemporaryDirectory() as td:
                O.ML_PY = ROOT / "osint_run.py"
                O.OSINT = pathlib.Path(td)
                r = O.stage_vision({}, [], faces=True)
                self.assertEqual(r["status"], "skipped")
                self.assertIn("warmup", r["reason"])
        finally:
            O.ML_PY, O.OSINT = old_py, old_osint


class HdCopies(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.td.name)
        self.old = O.IMAGES_DIR

    def tearDown(self):
        O.IMAGES_DIR = self.old
        self.td.cleanup()

    def test_save_image_is_a_no_op_without_a_case_folder(self):
        O.IMAGES_DIR = None
        self.assertEqual(O._save_image("ab" * 32, b"x"), "")

    def test_target_image_gets_an_hd_file_next_to_the_case(self):
        O.IMAGES_DIR = self.dir / "images"
        im = Image.new("RGB", (900, 700), (10, 120, 200))
        for x in range(100, 400):
            im.putpixel((x, x % 700), (250, 30, 30))
        src = self.dir / "ref.png"
        im.save(src)
        res = O.process_target_image(str(src))
        self.assertNotIn("error", res)
        self.assertTrue(res["hd_file"].startswith("images/"))
        hd = Image.open(self.dir / res["hd_file"])
        self.assertEqual(hd.format, "JPEG")
        self.assertLessEqual(max(hd.size), 640)

    def test_thumbresult_carries_hd_bytes(self):
        t = O.ThumbResult("d", "h", "u", "s", hd=b"jpeg")
        self.assertEqual(tuple(t), ("d", "h", "u", "s"))
        self.assertEqual(t.hd, b"jpeg")


class ReportOutput(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def _findings(self):
        accs = _accounts()
        accs[0]["avatar_src"] = "https://github.com/a.png"
        ti = {"filename": "ref.jpg", "sha256": "ab" * 32, "thumb": "data:image/jpeg;base64,x",
              "dimensions": "10×10", "reverse_links": [], "matches": []}
        f = {"input": {"name": ["T"], "username": [], "email": [], "phone": [], "domain": [], "file": [],
                       "image": ["/x/ref.jpg"], "notes": []},
             "identity": {}, "email": {}, "domain": {}, "phone": [], "metadata": [], "verified": accs,
             "target_images": [ti], "did_verify": True, "opsec": {}}
        vis = _result()
        vis["engine"] = {"faces": "insightface/buffalo_l (CPU)"}
        f["vision"] = vis
        O.merge_vision(f, vis, accs)
        return f

    def test_html_shows_face_tags_clusters_and_the_vision_line(self):
        f = self._findings()
        case = self.dir / "case.txt"
        case.write_text("name: T\n", encoding="utf-8")
        html = O.write_html_report(f, case, "20260914-120000").read_text(encoding="utf-8")
        self.assertIn("face match (cosine 0.96)", html)
        self.assertIn("visually similar (CLIP 0.86)", html)
        self.assertIn("Same face #1", html)
        self.assertIn("4 face(s) found", html)
        self.assertIn("face #1</span>", html)

    def test_html_marks_a_disputed_match_and_counts_the_confirmer(self):
        f = self._findings()
        accs = f["verified"]
        res = {"status": "ran", "ran": {"faces": True, "deepface": True}, "threshold": 0.5,
               "faces_total": 4, "engine": {"deepface": "deepface/x (CPU, confirmer)"},
               "face_matches": [{"a": "target:0", "b": "acct:0", "score": 0.9}],
               "deepface_confirms": [{"a": "target:0", "b": "acct:0", "status": "disputed",
                                      "insightface_score": 0.9,
                                      "models": [{"model": "Facenet512", "verified": False,
                                                  "distance": 0.4, "threshold": 0.3}]}]}
        f["vision"] = res
        O.merge_vision(f, res, accs)
        case = self.dir / "case.txt"
        case.write_text("name: T\n", encoding="utf-8")
        html = O.write_html_report(f, case, "20260914-120000").read_text(encoding="utf-8")
        self.assertIn("DeepFace does not confirm (Facenet512)", html)
        self.assertIn("DeepFace disputed", html)
        self.assertIn("1 disputed", html)
        self.assertIn(O.DISPUTED_MARK, html)

    def test_html_shows_the_vision_line_without_reference_images(self):
        f = self._findings()
        f["target_images"], f["input"]["image"] = [], []
        case = self.dir / "case.txt"
        case.write_text("name: T\n", encoding="utf-8")
        html = O.write_html_report(f, case, "20260914-120000").read_text(encoding="utf-8")
        self.assertIn("4 face(s) found", html)
        self.assertIn("Same face #1", html)

    def test_html_says_when_vision_did_not_run(self):
        f = self._findings()
        f["vision"] = {"status": "skipped", "reason": "not requested (--faces / --clip)"}
        case = self.dir / "case.txt"
        case.write_text("name: T\n", encoding="utf-8")
        html = O.write_html_report(f, case, "20260914-120000").read_text(encoding="utf-8")
        self.assertIn("not run — not requested", html)

    def test_auto_findings_lists_face_matches_and_groups(self):
        f = self._findings()
        case = self.dir / "case.txt"
        case.write_text("name: T\n", encoding="utf-8")
        O.update_target(case, f, "20260914-120000")
        txt = case.read_text(encoding="utf-8")
        self.assertIn("matched_target_image: [face 0.96] GitHub", txt)
        self.assertIn("same_face: #1 | GitHub https://github.com/pa | GitLab https://gitlab.com/pa", txt)


class VisionHelpers(unittest.TestCase):
    """Pure logic of ml/vision.py, importable without the ML libraries."""

    def test_pair_matches_skip_same_owner_and_sort_by_score(self):
        vecs = [("a", 1), ("b", 2), ("c", 3)]
        owners = {"a": "x.com", "b": "x.com", "c": "y.com"}
        dot = lambda p, q: {(1, 2): 0.9, (1, 3): 0.6, (2, 3): 0.8}[(p, q)]
        out = V.pair_matches(vecs, owners, 0.5, dot)
        self.assertEqual([(m["a"], m["b"], m["score"]) for m in out], [("b", "c", 0.8), ("a", "c", 0.6)])

    def test_collect_images_prefers_files_and_skips_generated_avatars(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            (d / "images").mkdir()
            Image.new("RGB", (300, 300), (1, 2, 3)).save(d / "images" / "hd.jpg")
            buf = io.BytesIO()
            Image.new("RGB", (40, 40), (1, 2, 3)).save(buf, "JPEG")
            thumb = "data:image/jpeg;base64," + __import__("base64").b64encode(buf.getvalue()).decode()
            case = {"target_images": [{"filename": "r", "hd_file": "images/hd.jpg", "thumb": thumb}],
                    "accounts": [{"site": "A", "user": "u", "url": "https://a.com/u", "state": "verified", "avatar": thumb},
                                 {"site": "B", "user": "u", "url": "https://b.com/u", "state": "verified", "avatar": thumb,
                                  "avatar_is_generated": True},
                                 {"site": "C", "user": "u", "url": "https://c.com/u", "state": "dead", "avatar": thumb}],
                    "metadata": [{"file": "/p/x.jpg", "meta": {"_thumbnail": thumb}}]}
            imgs = V.collect_images(case, base=d)
            keys = [i["key"] for i in imgs]
            self.assertEqual(keys, ["target:0", "acct:0", "exif:0"])
            self.assertEqual(imgs[0]["image"].size, (300, 300))     # the HD file, not the 40 px thumb
            self.assertEqual(imgs[1]["owner"], "a.com")

    def test_owner_strips_www(self):
        self.assertEqual(V._owner({"url": "https://www.example.co.uk/x", "site": "E"}), "example.co.uk")
        self.assertEqual(V._owner({"url": "", "site": "Site"}), "site")


if __name__ == "__main__":
    unittest.main()
