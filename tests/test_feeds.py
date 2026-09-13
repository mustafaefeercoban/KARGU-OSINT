#!/usr/bin/env python3
"""Offline tests for the feed modules: GDELT error mapping, Telegram row shaping, Sentinel gating."""
import io
import json
import pathlib
import sys
import tempfile
import types
import unittest
import urllib.error

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from feeds import gdelt, sentinel, telegram_listener, telegram_search  # noqa: E402


class _Opener:
    def __init__(self, exc=None, body=b""):
        self.exc, self.body = exc, body

    def open(self, req, timeout=0):
        if self.exc:
            raise self.exc
        return io.BytesIO(self.body)


class Gdelt(unittest.TestCase):

    def _with(self, opener):
        old = gdelt.urllib.request.build_opener
        gdelt.urllib.request.build_opener = lambda *a, **k: opener
        try:
            return gdelt.search('"Example Org"')
        finally:
            gdelt.urllib.request.build_opener = old

    def test_rate_limit_is_named(self):
        err = urllib.error.HTTPError("u", 429, "Too Many", {}, None)
        r = self._with(_Opener(exc=err))
        self.assertEqual(r["status"], 429)
        self.assertIn("5 seconds", r["error"])
        self.assertEqual(r["articles"], [])

    def test_html_answer_and_network_error(self):
        self.assertIn("no JSON", self._with(_Opener(body=b"<html>oops"))["error"])
        self.assertIn("unreachable", self._with(_Opener(exc=OSError("down")))["error"])

    def test_articles_are_trimmed_to_the_fields_the_panel_uses(self):
        body = json.dumps({"articles": [{"url": "https://n.example/a", "title": "T", "seendate": "20260914T100000Z",
                                         "domain": "n.example", "language": "English", "sourcecountry": "Turkey",
                                         "socialimage": "x"}]}).encode()
        r = self._with(_Opener(body=body))
        self.assertEqual(r["articles"], [{"url": "https://n.example/a", "title": "T", "seendate": "20260914T100000Z",
                                          "domain": "n.example", "language": "English", "sourcecountry": "Turkey"}])


class Telegram(unittest.TestCase):

    def test_row_builds_a_link_only_for_public_channels(self):
        import datetime
        msg = types.SimpleNamespace(id=7, raw_text="x" * 600, date=datetime.datetime(2026, 9, 14, 10, 0), chat_id=5)
        pub = types.SimpleNamespace(username="chan", title="Channel")
        r = telegram_search._row(msg, pub)
        self.assertEqual(r["link"], "https://t.me/chan/7")
        self.assertEqual(len(r["text"]), 500)
        self.assertEqual(r["date"], "2026-09-14T10:00:00")
        self.assertEqual(telegram_search._row(msg, None)["chat"], "5")

    def test_listener_seeds_come_from_the_case_export(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            (d / "c.json").write_text(json.dumps({"seeds": {"names": ["Ayşe Nur"], "usernames": ["aysegunes", "ab"],
                                                            "emails": ["a@b.co"], "phones": [], "domains": []}}))
            self.assertEqual(telegram_listener._seeds(d), ["a@b.co", "aysegunes", "ayşe nur"])
            self.assertEqual(telegram_listener._seeds(pathlib.Path(td) / "missing"), [])


class Sentinel(unittest.TestCase):

    def test_without_credentials_it_skips_instead_of_failing(self):
        old = sentinel._env
        sentinel._env = lambda: {}
        try:
            r = sentinel.quicklooks(39.9, 32.8)
        finally:
            sentinel._env = old
        self.assertIn("COPERNICUS_CLIENT_ID", r["skipped"])
        self.assertEqual(r["items"], [])


class WizardImageField(unittest.TestCase):

    def test_image_validator_and_profile_text(self):
        import osint_wizard as W
        self.assertEqual(W.v_image("https://x.example/p.jpg"), (True, "https://x.example/p.jpg"))
        self.assertFalse(W.v_image("/definitely/not/here.jpg")[0])
        self.assertIn("not an image", W.v_image(str(ROOT / "README.md"))[1])
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "a.PNG"
            p.write_bytes(b"x")
            self.assertEqual(W.v_image(str(p)), (True, str(p)))
        self.assertIn("image", [f["key"] for f in W.FIELDS])
        txt = W.build_profile_text({"name": ["T"], "image": ["/p/a.jpg", "https://x/y.jpg"]}, "case")
        self.assertIn("image: /p/a.jpg\nimage: https://x/y.jpg\n", txt)


if __name__ == "__main__":
    unittest.main()
