#!/usr/bin/env python3
"""Offline tests for dashboard/server.py: access gate, CSRF, intake, case lookup, inline JSON safety."""
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest

from PIL import Image

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("dash_server", ROOT / "dashboard" / "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


S = _load()


def _png_bytes():
    buf = io.BytesIO()
    Image.new("RGB", (20, 20), (200, 10, 10)).save(buf, "PNG")
    return buf.getvalue()


class Base(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        S.CASES = pathlib.Path(self.td.name)
        S._CACHE.clear()
        S.JOBS.clear()
        S.app.config["TESTING"] = True
        self.c = S.app.test_client()
        self.c.set_cookie(S.COOKIE, S.ACCESS_TOKEN, domain="localhost")

    def tearDown(self):
        self.td.cleanup()

    def _case(self, folder, stem, doc=None, sidecar=None):
        d = S.CASES / folder
        d.mkdir(parents=True, exist_ok=True)
        doc = doc or {"schema": "kargu-case/1", "generated": "20260914-120000", "stats": {"verified": 2, "accounts": 3},
                      "accounts": [], "opsec": {"egress": {"ip": "1.2.3.4", "mullvad": True}}}
        (d / f"{stem}.json").write_text(json.dumps(doc), encoding="utf-8")
        if sidecar is not None:
            (d / f"{stem}{S.SIDECAR}").write_text(json.dumps(sidecar), encoding="utf-8")
        return d


class AccessGate(Base):

    def test_no_token_is_403(self):
        c = S.app.test_client()
        self.assertEqual(c.get("/").status_code, 403)
        self.assertEqual(c.post("/api/run").status_code, 403)

    def test_token_in_url_sets_cookie_and_redirects(self):
        c = S.app.test_client()
        r = c.get(f"/?t={S.ACCESS_TOKEN}")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(c.get("/").status_code, 200)


class AccessGateEdgeCases(Base):

    def test_non_ascii_token_and_cookie_get_403_not_500(self):
        c = S.app.test_client()
        self.assertEqual(c.get("/?t=%C3%BC").status_code, 403)
        c.set_cookie(S.COOKIE, "ü", domain="localhost")
        self.assertEqual(c.get("/").status_code, 403)

    def test_static_route_does_not_leave_its_root(self):
        self.assertEqual(self.c.get("/static/dash.js").status_code, 200)
        self.assertEqual(self.c.get("/static/leaflet/leaflet.css").status_code, 200)
        for p in ("/static/../server.py", "/static/..%2Fserver.py", "/static/../install-ml.sh",
                  "/static/../templates/case.html", "/static/leaflet/../../server.py"):
            self.assertEqual(self.c.get(p).status_code, 404, p)


class CaseLookup(Base):

    def test_sidecar_is_not_listed_as_a_case_and_newest_stem_wins(self):
        self._case("demo_20260101-000000", "demo", sidecar={"status": "ran"})
        newer = self._case("demo_20260202-000000", "demo")
        rows = S._cases()
        self.assertEqual([r[0] for r in rows], ["demo_20260202-000000", "demo_20260101-000000"])
        self.assertEqual(S._find_case("demo"), newer / "demo.json")
        self.assertEqual(S._find_case("demo_20260101-000000").parent.name, "demo_20260101-000000")
        self.assertIsNone(S._find_case("../etc"))
        self.assertIsNone(S._find_case("nope"))

    def test_case_page_inlines_json_without_a_closing_script_tag(self):
        doc = {"schema": "kargu-case/1", "generated": "20260914-120000", "stats": {},
               "accounts": [{"site": "X", "description": "</script><script>alert(1)</script>"}]}
        self._case("evil_20260101-000000", "evil", doc)
        r = self.c.get("/case/evil")
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertNotIn("</script><script>alert", body)
        self.assertIn("\\u003c/script>", body)

    def test_sidecar_overrides_vision_in_the_served_doc(self):
        self._case("v_20260101-000000", "v", sidecar={"status": "ran", "source": "dashboard", "faces_total": 3})
        r = self.c.get("/api/case/v")
        self.assertEqual(r.get_json()["vision"]["faces_total"], 3)

    def test_case_list_marks_vision_from_the_sidecar_too(self):
        self._case("a_20260101-000000", "a", sidecar={"status": "ran"})
        self._case("b_20260102-000000", "b")
        rows = {r["stem"]: r["faces"] for r in S._case_rows()}
        self.assertEqual(rows, {"a": True, "b": False})

    def test_index_and_new_render(self):
        self._case("demo_20260101-000000", "demo")
        self.assertIn("demo_20260101-000000", self.c.get("/").get_data(as_text=True))
        page = self.c.get("/new").get_data(as_text=True)
        self.assertIn(S.CSRF_TOKEN, page)
        self.assertIn('name="photos"', page)
        self.assertEqual(self.c.get("/cases").status_code, 302)


class Intake(Base):

    def setUp(self):
        super().setUp()
        self.launched = []
        S._worker = lambda jid, cmd, folder: (self.launched.append(cmd), S.JOBS[jid].update(status="done"))

    def _post(self, data, headers=None):
        h = {"Origin": "http://localhost", **(headers or {})}
        return self.c.post("/api/run", data=data, headers=h, content_type="multipart/form-data")

    def test_missing_csrf_and_foreign_origin_are_rejected(self):
        self.assertEqual(self._post({"name": "T"}).status_code, 403)
        r = self._post({"csrf": S.CSRF_TOKEN, "name": "T"}, {"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.launched, [])
        self.assertEqual(list(S.CASES.iterdir()), [])

    def test_empty_form_and_invalid_values_do_not_create_a_case(self):
        self.assertEqual(self._post({"csrf": S.CSRF_TOKEN}).status_code, 400)
        r = self._post({"csrf": S.CSRF_TOKEN, "email": "not-an-email"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("E-mail", r.get_json()["error"])
        self.assertEqual(list(S.CASES.iterdir()), [])

    def test_photos_become_image_lines_and_flags_reach_the_command(self):
        data = {"csrf": S.CSRF_TOKEN, "name": "Ayşe Nur Güneş", "username": "aysegunes, ayse_92", "api": "on",
                "faces": "on", "clip": "on", "photos": [(io.BytesIO(_png_bytes()), "a.png"), (io.BytesIO(_png_bytes()), "b.png")]}
        old = S.ML_PY
        S.ML_PY = ROOT / "osint_run.py"       # any existing path stands in for the venv
        try:
            r = self._post(data)
        finally:
            S.ML_PY = old
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        j = r.get_json()
        folder = S.CASES / j["case"]
        self.assertTrue(j["case"].startswith("ayse-nur-gunes_"))
        refs = sorted(p.name for p in (folder / "refs").iterdir())
        self.assertEqual(refs, ["ref01.png", "ref02.png"])
        txt = (folder / "ayse-nur-gunes.txt").read_text(encoding="utf-8")
        self.assertIn(f"image: {folder / 'refs' / 'ref01.png'}", txt)
        self.assertIn("username: aysegunes\n", txt)
        cmd = self.launched[0]
        self.assertIn("--faces", cmd)
        self.assertIn("--clip", cmd)
        self.assertIn("--no-derive", cmd)
        self.assertNotIn("--no-api", cmd)
        job = self.c.get(f"/api/job/{j['job_id']}").get_json()
        self.assertEqual(job["case"], j["case"])

    def test_non_image_upload_is_rejected_before_anything_is_written(self):
        data = {"csrf": S.CSRF_TOKEN, "name": "T", "photos": (io.BytesIO(b"<html>"), "x.png")}
        r = self._post(data)
        self.assertEqual(r.status_code, 400)
        self.assertIn("not a JPEG", r.get_json()["error"])
        self.assertEqual(list(S.CASES.iterdir()), [])


class Feeds(Base):

    def test_telegram_unconfigured_still_returns_listener_hits(self):
        d = self._case("t_20260101-000000", "t")
        (d / "telegram.jsonl").write_text(
            '{"when": "2026-09-14T10:00:00+00:00", "channel": "chan", "id": 1, "text": "hello aysegunes", "hit": ["aysegunes"]}\n'
            'not json\n{"when": "x", "channel": "chan", "id": 2, "text": "noise", "hit": []}\n', encoding="utf-8")
        old = S._telegram_configured
        S._telegram_configured = lambda: False
        try:
            r = self.c.get("/api/telegram?q=x&case=t").get_json()
        finally:
            S._telegram_configured = old
        self.assertIn("not configured", r["error"])
        self.assertEqual([h["id"] for h in r["listener"]], [1])

    def test_gdelt_needs_a_query_and_sentinel_needs_coordinates(self):
        self.assertEqual(self.c.get("/api/gdelt").get_json()["error"], "no query")
        self.assertIn("lat", self.c.get("/api/sentinel?lat=x").get_json()["error"])

    def test_telegram_subprocess_failure_is_an_error_not_an_empty_result(self):
        self._case("t_20260101-000000", "t")
        calls = []

        class R:
            returncode, stdout, stderr = 2, "", "usage: telegram_search.py ... unrecognized arguments"

        old_cfg, old_run, old_ml = S._telegram_configured, S.subprocess.run, S.ML_PY
        S._telegram_configured, S.subprocess.run, S.ML_PY = (lambda: True), (lambda cmd, **kw: (calls.append(cmd), R())[1]), ROOT / "osint_run.py"
        try:
            r = self.c.get("/api/telegram?q=--login&case=t").get_json()
        finally:
            S._telegram_configured, S.subprocess.run, S.ML_PY = old_cfg, old_run, old_ml
        self.assertIn("Telegram search failed", r["error"])
        self.assertEqual(calls[0][-2:], ["--", "--login"])   # the query can never become an option

    def test_vision_without_venv_explains_the_install(self):
        self._case("v_20260101-000000", "v")
        old = S.ML_PY
        S.ML_PY = pathlib.Path("/nonexistent")
        try:
            r = self.c.post("/api/vision/v?faces=1").get_json()
            self.assertIn("install-ml.sh", r["error"])
            self.assertEqual(self.c.post("/api/vision/v").get_json()["error"][:7], "nothing")
            self.assertIn("install-ml.sh", self.c.post("/api/clip/v?q=hat").get_json()["error"])
        finally:
            S.ML_PY = old


if __name__ == "__main__":
    unittest.main()
