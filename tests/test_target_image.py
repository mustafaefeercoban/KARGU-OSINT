#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for user-supplied target reference images and dual visual results."""

import io
import os
import pathlib
import sys
import tempfile
import unittest
from PIL import Image

# Ensure project root is on sys.path
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import osint_run as O


class TargetImageParsing(unittest.TestCase):

    def _parse(self, text):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "t.txt"
            p.write_text(text, encoding="utf-8")
            return O.parse_target(p)

    def test_image_in_target_file_is_parsed(self):
        """image: paths expand ~ and remote URLs are preserved as-is."""
        prof = self._parse(
            "name: John Doe\n"
            "image: ~/my_photo.jpg\n"
            "image: https://example.com/target.png\n"
        )
        self.assertIn("image", prof)
        self.assertEqual(len(prof["image"]), 2)
        # First entry expanded tilde
        self.assertTrue(prof["image"][0].startswith("/"))
        self.assertTrue(prof["image"][0].endswith("my_photo.jpg"))
        # Second entry kept URL intact
        self.assertEqual(prof["image"][1], "https://example.com/target.png")


class ProcessTargetImage(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def _create_image(self, name, size=(100, 100), color=(180, 70, 40)):
        p = self.dir / name
        im = Image.new("RGB", size, color)
        # draw a simple pattern so it's not totally flat
        for x in range(20, 80):
            for y in range(20, 80):
                im.putpixel((x, y), (255 - color[0], 255 - color[1], 100))
        im.save(p, "JPEG")
        return p

    def test_process_local_image_generates_hashes_and_thumbnail(self):
        """A local image produces SHA-256, dHash, pHash, center crops, and thumbnail."""
        p = self._create_image("target.jpg")
        res = O.process_target_image(str(p))

        self.assertNotIn("error", res)
        self.assertEqual(res["filename"], "target.jpg")
        self.assertFalse(res["is_url"])
        self.assertEqual(len(res["sha256"]), 64)
        self.assertEqual(res["avatar_sha256"], res["sha256"])
        self.assertTrue(res["thumb"].startswith("data:image/jpeg;base64,"))
        self.assertEqual(res["dimensions"], "100×100")

        hashes = res["avatar_hashes"]
        self.assertIn("dhash", hashes)
        self.assertIn("dhash_center", hashes)
        self.assertIn("phash", hashes)
        self.assertIn("phash_center", hashes)
        self.assertIsInstance(hashes["dhash"], int)
        self.assertIsInstance(hashes["phash"], int)

        # Reverse links for local file should have search portal URLs
        rev = res["reverse_links"]
        self.assertTrue(len(rev) >= 4)
        names = [n for n, u in rev]
        self.assertIn("Google Lens", names)
        self.assertIn("Yandex Images", names)

    def test_process_missing_file_returns_error(self):
        """Missing local path returns structured error dictionary."""
        res = O.process_target_image("/nonexistent/path/to/target.jpg")
        self.assertIn("error", res)
        self.assertIn("file not found", res["error"])

    def test_process_url_not_public_returns_error(self):
        """Loopback and private URLs are refused by _fetch_target_ok."""
        res = O.process_target_image("http://127.0.0.1/evil.jpg")
        self.assertIn("error", res)
        self.assertIn("not a public http(s) host", res["error"])


class TargetImageMatching(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def test_exact_same_image_matches_as_strong(self):
        """An account avatar that shares exact bytes with the target image matches with 'strong' tier."""
        im = Image.new("RGB", (96, 96), (100, 150, 200))
        for i in range(10, 86):
            im.putpixel((i, i), (255, 50, 50))
        p = self.dir / "ref.jpg"
        im.save(p, "JPEG")

        timg = O.process_target_image(str(p))
        self.assertNotIn("error", timg)

        # Create simulated verified account with the same image data
        buf = io.BytesIO()
        im.save(buf, "JPEG")
        acct = {
            "site": "GitHub",
            "user": "johndoe",
            "url": "https://github.com/johndoe",
            "display_name": "John Doe",
            "avatar_sha256": timg["sha256"],
            "avatar_hash": timg["avatar_hash"],
            "avatar_hashes": timg["avatar_hashes"],
            "avatar": timg["thumb"],
        }

        O.match_target_images_against_accounts([timg], [acct])
        self.assertEqual(len(timg["matches"]), 1)
        match = timg["matches"][0]
        self.assertEqual(match["site"], "GitHub")
        self.assertEqual(match["user"], "johndoe")
        self.assertEqual(match["tier"], "strong")
        self.assertEqual(acct.get("target_image_match"), "strong")

    def test_perceptual_similar_image_matches_as_possible(self):
        """A slightly cropped / recompressed image matches with 'possible' tier."""
        im1 = Image.new("RGB", (120, 120), (50, 120, 180))
        for x in range(25, 95):
            for y in range(25, 95):
                im1.putpixel((x, y), (200, 80, 40))
        p = self.dir / "ref.jpg"
        im1.save(p, "JPEG", quality=90)

        timg = O.process_target_image(str(p))

        # Recompress slightly differently (simulate CDN re-encode)
        buf = io.BytesIO()
        im1.save(buf, "JPEG", quality=75)
        blob2 = buf.getvalue()
        im2 = Image.open(io.BytesIO(blob2))

        acct = {
            "site": "Twitter",
            "user": "johndoe",
            "url": "https://twitter.com/johndoe",
            "display_name": "John",
            "avatar_sha256": "different_sha256_hash_here_1234567890",
            "avatar_hash": f"{O._dhash(im2):016x}",
            "avatar_hashes": {
                "dhash": O._dhash(im2),
                "dhash_center": O._dhash(im2.crop((10, 10, 110, 110))),
                "phash": O._phash(im2),
                "phash_center": O._phash(im2.crop((10, 10, 110, 110))),
            },
            "avatar": timg["thumb"],
        }

        O.match_target_images_against_accounts([timg], [acct])
        self.assertEqual(len(timg["matches"]), 1)
        self.assertEqual(timg["matches"][0]["tier"], "possible")
        self.assertEqual(timg["matches"][0]["site"], "Twitter")

    def test_different_image_does_not_match(self):
        """Completely different images do not match."""
        im1 = Image.new("RGB", (80, 80), (255, 255, 255))
        for i in range(80):
            im1.putpixel((i, i), (0, 0, 0))
        p = self.dir / "ref.jpg"
        im1.save(p, "JPEG")
        timg = O.process_target_image(str(p))

        # Different image
        im2 = Image.new("RGB", (80, 80), (0, 180, 0))
        for x in range(30, 50):
            for y in range(30, 50):
                im2.putpixel((x, y), (255, 0, 255))

        acct = {
            "site": "Reddit",
            "user": "someone_else",
            "url": "https://reddit.com/u/someone_else",
            "avatar_sha256": "completely_different_sha",
            "avatar_hash": f"{O._dhash(im2):016x}",
            "avatar_hashes": {
                "dhash": O._dhash(im2),
                "dhash_center": O._dhash(im2),
                "phash": O._phash(im2),
                "phash_center": O._phash(im2),
            },
        }

        O.match_target_images_against_accounts([timg], [acct])
        self.assertEqual(timg["matches"], [])


class TwoResultReportLayout(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def _findings_with_images(self, target_images=None, verified=None):
        return {
            "input": {"name": ["Target Person"], "username": ["tp"], "email": [],
                      "phone": [], "domain": [], "file": [], "image": [], "notes": []},
            "identity": {}, "email": {}, "domain": {}, "phone": [], "metadata": [],
            "verified": verified or [],
            "target_images": target_images or [],
            "did_verify": True,
            "opsec": {},
        }

    def test_both_subsections_render_in_html_report(self):
        """Section 2 renders both 2.1 (Operator Reference Images) and 2.2 (Auto-Discovered Visuals)."""
        f = self._findings_with_images()
        case_txt = self.dir / "case.txt"
        case_txt.write_text("name: Target Person\n", encoding="utf-8")

        html_path = O.write_html_report(f, case_txt, "20260914-120000")
        content = html_path.read_text(encoding="utf-8")

        self.assertIn("2 · Visual & Identity Intelligence", content)
        self.assertIn("2.1 · Operator reference images", content)
        self.assertIn("2.2 · Auto-discovered profile visuals &amp; identity", content)

    def test_matched_account_is_displayed_under_operator_section(self):
        """When operator target image matches a verified account, the match appears in Section 2.1."""
        timg = {
            "source": "/path/to/my_face.jpg",
            "filename": "my_face.jpg",
            "is_url": False,
            "sha256": "1234567890abcdef" * 4,
            "thumb": "data:image/jpeg;base64,fakeimagecontent",
            "dimensions": "120×120",
            "reverse_links": [("Google Lens", "https://lens.google.com/")],
            "matches": [{
                "site": "GitHub",
                "user": "target_dev",
                "url": "https://github.com/target_dev",
                "display_name": "Target Developer",
                "tier": "strong",
                "avatar": "data:image/jpeg;base64,fakeimagecontent",
                "avatar_src": "https://avatars.githubusercontent.com/u/999",
                "kind": "avatar",
            }],
        }
        ver_acct = {
            "site": "GitHub",
            "user": "target_dev",
            "url": "https://github.com/target_dev",
            "display_name": "Target Developer",
            "state": "verified",
            "avatar": "data:image/jpeg;base64,fakeimagecontent",
            "avatar_sha256": timg["sha256"],
            "via": ["sherlock"],
        }
        f = self._findings_with_images(target_images=[timg], verified=[ver_acct])
        case_txt = self.dir / "case.txt"
        case_txt.write_text("name: Target Person\nimage: /path/to/my_face.jpg\n", encoding="utf-8")

        html_path = O.write_html_report(f, case_txt, "20260914-120000")
        content = html_path.read_text(encoding="utf-8")

        # In subsection 2.1:
        self.assertIn("my_face.jpg", content)
        self.assertIn("strong match (byte-identical)", content)
        self.assertIn("https://github.com/target_dev", content)
        self.assertIn("Matched Accounts <span class='tag ok'>1 match(es)</span>", content)


if __name__ == "__main__":
    unittest.main()
