#!/usr/bin/env python3
"""Offline tests for the local vision stage: merge rules, HD copies, report/AUTO-FINDINGS output."""
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
