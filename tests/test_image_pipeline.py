import unittest
import io
from PIL import Image, ImageDraw

import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_engine():
    """Import osint_run.py by path; the project is scripts, not a package."""
    spec = importlib.util.spec_from_file_location("osint_run", ROOT / "osint_run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_O = _load_engine()
_avatar_candidates = _O._avatar_candidates
_is_generic_avatar_url = _O._is_generic_avatar_url
_dhash = _O._dhash
_phash = _O._phash
_is_generated_avatar = _O._is_generated_avatar
_images_match = _O._images_match
group_by_photo = _O.group_by_photo
_summarize_exif = _O._summarize_exif
_extract_exif_thumbnail = _O._extract_exif_thumbnail
tool = _O.tool
stage_metadata = _O.stage_metadata
ThumbResult = _O.ThumbResult
_host = _O._host



class TestAvatarCandidates(unittest.TestCase):
    """Tests for HTML parsing and avatar candidate URL extraction."""

    def test_json_ld_string_and_object(self):
        # Format 1: Simple string in JSON-LD
        doc1 = """
        <!DOCTYPE html><html><head>
        <script type="application/ld+json">
        {
          "@context": "https://schema.org",
          "@type": "Person",
          "name": "Alice Example",
          "image": "https://cdn.example.com/profiles/alice_photo.jpg"
        }
        </script></head><body></body></html>
        """
        cands1 = _avatar_candidates(doc1, url="https://example.com/alice")
        self.assertIn("https://cdn.example.com/profiles/alice_photo.jpg", cands1)

        # Format 2: ImageObject with url property
        doc2 = """
        <script type="application/ld+json">
        {
          "@context": "https://schema.org",
          "@type": "ProfilePage",
          "mainEntity": {
            "@type": "Person",
            "image": {
              "@type": "ImageObject",
              "url": "https://cdn.example.com/profiles/bob_large.png"
            }
          }
        }
        </script>
        """
        cands2 = _avatar_candidates(doc2, url="https://example.com/bob")
        self.assertIn("https://cdn.example.com/profiles/bob_large.png", cands2)

    def test_link_rel_and_microdata(self):
        doc = """
        <html><head>
        <link rel="image_src" href="https://cdn.example.com/avatars/avatar1.jpg">
        <meta itemprop="image" content="https://cdn.example.com/avatars/avatar2.jpg">
        </head><body>
        <img itemprop="image" src="/avatars/relative_avatar.png">
        </body></html>
        """
        cands = _avatar_candidates(doc, url="https://example.com/user/profile")
        self.assertIn("https://cdn.example.com/avatars/avatar1.jpg", cands)
        self.assertIn("https://cdn.example.com/avatars/avatar2.jpg", cands)
        # Verify relative URL resolution
        self.assertIn("https://example.com/avatars/relative_avatar.png", cands)

    def test_lazy_load_and_srcset(self):
        doc = """
        <div>
          <img class="user-avatar" data-src="https://cdn.example.com/lazy_user.jpg" src="/blank.gif">
          <img class="profile-pic" data-original="https://cdn.example.com/original_user.jpg">
          <img class="avatar" srcset="https://cdn.example.com/srcset_1x.jpg 1x, https://cdn.example.com/srcset_2x.jpg 2x">
        </div>
        """
        cands = _avatar_candidates(doc, url="https://example.com")
        self.assertIn("https://cdn.example.com/lazy_user.jpg", cands)
        self.assertIn("https://cdn.example.com/original_user.jpg", cands)
        self.assertTrue(any("srcset" in c for c in cands))

    def test_inline_background_image(self):
        doc = """
        <div class="profile-user-avatar" style="width:100px; height:100px; background-image: url('https://cdn.example.com/bg_user.jpg');"></div>
        <span class="user-photo" style="background: url(/bg_relative.jpg) center no-repeat;"></span>
        """
        cands = _avatar_candidates(doc, url="https://example.com/user")
        self.assertIn("https://cdn.example.com/bg_user.jpg", cands)
        self.assertIn("https://example.com/bg_relative.jpg", cands)

    def test_top_site_extractors(self):
        # GitHub
        gh_doc = """
        <img class="avatar avatar-user width-full" src="https://avatars.githubusercontent.com/u/12345678?v=4">
        """
        gh_cands = _avatar_candidates(gh_doc, url="https://github.com/octocat", site="GitHub", user="octocat")
        self.assertTrue(any("avatars.githubusercontent.com" in c for c in gh_cands))
        self.assertIn("https://github.com/octocat.png", gh_cands)

        # Telegram
        tg_doc = """
        <img class="tgme_page_photo_image" src="https://cdn4.telesco.pe/file/abcdef123456.jpg">
        """
        tg_cands = _avatar_candidates(tg_doc, url="https://t.me/durov", site="Telegram")
        self.assertIn("https://cdn4.telesco.pe/file/abcdef123456.jpg", tg_cands)

        # Chess.com
        chess_doc = """
        <img class="avatar-component" src="https://images.chesscomfiles.com/uploads/v1/user/987654.12345678.160x160o.jpg">
        """
        chess_cands = _avatar_candidates(chess_doc, url="https://www.chess.com/member/magnus", site="Chess.com")
        self.assertTrue(any("images.chesscomfiles.com/uploads/v1/user/987654" in c for c in chess_cands))

        # TradingView
        tv_doc = """
        <img class="tv-user-avatar" src="https://s3.tradingview.com/userpics/12345-mid.png">
        """
        tv_cands = _avatar_candidates(tv_doc, url="https://www.tradingview.com/u/trader1", site="TradingView")
        self.assertIn("https://s3.tradingview.com/userpics/12345-mid.png", tv_cands)

        # YouTube
        yt_doc = """
        <link rel="image_src" href="https://yt3.ggpht.com/ytc/AIdro_dummy123=s176-c-k-c0x00ffffff-no-rj">
        """
        yt_cands = _avatar_candidates(yt_doc, url="https://www.youtube.com/@creator", site="YouTube")
        self.assertTrue(any("yt3.ggpht.com" in c for c in yt_cands))


class TestGenericImageFilter(unittest.TestCase):
    """Tests for filename/basename vs full-url generic image filtering."""

    def test_valid_avatar_with_share_in_path_is_kept(self):
        # A legitimate avatar whose URL path happens to contain 'share' or 'cover'
        url = "https://cdn.example.com/share/users/99482/profile.jpg"
        self.assertFalse(_is_generic_avatar_url(url))

        url2 = "https://example.com/data/cover/user_photo_square.png"
        self.assertFalse(_is_generic_avatar_url(url2))

    def test_generic_placeholders_are_rejected(self):
        self.assertTrue(_is_generic_avatar_url("https://example.com/assets/default_avatar.png"))
        self.assertTrue(_is_generic_avatar_url("https://example.com/img/noavatar.png"))
        self.assertTrue(_is_generic_avatar_url("https://example.com/images/share-card.jpg"))
        self.assertTrue(_is_generic_avatar_url("https://cdn.example.com/placeholder.jpg"))
        self.assertTrue(_is_generic_avatar_url("https://site.com/favicon.ico"))


class TestPerceptualHashing(unittest.TestCase):
    """Tests for 64-bit dHash, DCT pHash, and center-crop resilience."""

    def setUp(self):
        # Create a synthetic image with varying color patches and details
        self.im = Image.new("RGB", (120, 120), (240, 240, 240))
        d = ImageDraw.Draw(self.im)
        d.rectangle((20, 20, 100, 100), fill=(50, 100, 150))
        d.ellipse((35, 35, 85, 85), fill=(200, 80, 40))
        d.line((10, 10, 110, 110), fill=(0, 255, 100), width=3)

    def test_phash_output(self):
        ph = _phash(self.im)
        self.assertIsInstance(ph, int)
        self.assertGreater(ph, 0)
        self.assertLess(ph, 1 << 64)

    def test_crop_resilience_matching(self):
        # Crop 5% from edges (90% centered)
        w, h = self.im.size
        im_crop = self.im.crop((int(w * 0.05), int(h * 0.05), int(w * 0.95), int(h * 0.95)))

        # Center crop on original
        cw, ch = int(w * 0.85), int(h * 0.85)
        im_center = self.im.crop(((w - cw) // 2, (h - ch) // 2, (w + cw) // 2, (h + ch) // 2))

        # Hashes
        dh_full = _dhash(self.im)
        dh_center = _dhash(im_center)
        ph_full = _phash(self.im)
        ph_center = _phash(im_center)

        crop_hashes = {
            "dhash": _dhash(im_crop),
            "dhash_center": _dhash(im_crop),
            "phash": _phash(im_crop),
            "phash_center": _phash(im_crop),
        }

        acct1 = {
            "url": "https://github.com/alice",
            "avatar_hash": f"{dh_full:016x}",
            "avatar_hashes": {"dhash": dh_full, "dhash_center": dh_center, "phash": ph_full, "phash_center": ph_center},
        }
        acct2 = {
            "url": "https://gitlab.com/alice",
            "avatar_hash": f"{crop_hashes['dhash']:016x}",
            "avatar_hashes": crop_hashes,
        }

        matched, tier = _images_match(acct1, acct2, max_dhash=6, max_phash=8)
        self.assertTrue(matched, "Cropped version of the same image should match with center crop and pHash")

    def test_different_images_do_not_match(self):
        im_diff = Image.new("RGB", (120, 120), (10, 10, 10))
        d = ImageDraw.Draw(im_diff)
        d.ellipse((10, 10, 60, 60), fill=(255, 255, 0))

        acct1 = {
            "url": "https://github.com/alice",
            "avatar_hashes": {"dhash": _dhash(self.im), "phash": _phash(self.im)},
        }
        acct2 = {
            "url": "https://github.com/bob",
            "avatar_hashes": {"dhash": _dhash(im_diff), "phash": _phash(im_diff)},
        }
        matched, _ = _images_match(acct1, acct2)
        self.assertFalse(matched)


class TestGeneratedAvatarDetection(unittest.TestCase):
    """Tests for detecting initial/letter avatars and keeping them out of clusters."""

    def test_letter_avatar_is_detected(self):
        # Circular colored background + initials 'AG'
        im = Image.new("RGB", (100, 100), (41, 128, 185))
        d = ImageDraw.Draw(im)
        d.text((35, 35), "AG", fill=(255, 255, 255))

        self.assertTrue(_is_generated_avatar(im))

    def test_real_photo_is_not_detected_as_generated(self):
        # Synthetic textured photo with smooth gradients and noise
        im = Image.new("RGB", (100, 100))
        px = im.load()
        for y in range(100):
            for x in range(100):
                px[x, y] = ((x * 3) % 256, (y * 3) % 256, (x + y * 2) % 256)
        self.assertFalse(_is_generated_avatar(im))

    def test_group_by_photo_excludes_generated_avatars(self):
        # Two different users with initials avatar producing identical hashes
        acct1 = {
            "url": "https://github.com/user1",
            "site": "GitHub",
            "avatar_hash": "1122334455667788",
            "avatar_is_generated": True,
        }
        acct2 = {
            "url": "https://twitter.com/user2",
            "site": "Twitter",
            "avatar_hash": "1122334455667788",
            "avatar_is_generated": True,
        }
        groups = group_by_photo([acct1, acct2])
        self.assertEqual(len(groups), 0, "Generated letter avatars must not form cross-platform groups")
        self.assertIn("generated/letter avatar", acct1.get("photo_note", ""))


class TestExifSummarization(unittest.TestCase):
    """Tests for forensic EXIF field summarization."""

    def test_summarize_exif(self):
        meta = {
            "Make": "Canon",
            "Model": "EOS 5D Mark IV",
            "LensModel": "EF24-70mm f/2.8L II USM",
            "Software": "Adobe Lightroom 12.0",
            "Artist": "John Doe Photography",
            "DateTimeOriginal": "2024:06:15 14:23:45",
            "GPSLatitude": 41.0082,
            "GPSLongitude": 28.9784,
            "GPSAltitude": 45.2,
            "Exposure": "1/250",
            "FNumber": 2.8,
            "ISO": 100,
        }
        sm = _summarize_exif(meta)
        self.assertIn("Canon EOS 5D Mark IV", sm["Device"])
        self.assertIn("EF24-70mm", sm["Device"])
        self.assertEqual(sm["Software"], "Adobe Lightroom 12.0")
        self.assertEqual(sm["Creator"], "John Doe Photography")
        self.assertEqual(sm["DateTime"], "2024:06:15 14:23:45")
        self.assertIn("41.0082, 28.9784", sm["GPS"])

    def test_extract_exif_thumbnail(self):
        import tempfile, os, subprocess
        et = tool("exiftool")
        if not et:
            self.skipTest("exiftool not available")

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f_img:
            img_path = f_img.name
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f_th:
            th_path = f_th.name

        try:
            im = Image.new("RGB", (300, 300), (100, 150, 200))
            im.save(img_path, "JPEG")
            im_th = Image.new("RGB", (120, 120), (200, 100, 50))
            im_th.save(th_path, "JPEG")

            subprocess.run([et, "-overwrite_original", f"-ThumbnailImage<={th_path}", img_path],
                           capture_output=True)

            res = stage_metadata(img_path)
            self.assertIsNotNone(res.get("meta", {}).get("_thumbnail"))
            self.assertTrue(res["meta"]["_thumbnail"].startswith("data:image/jpeg;base64,"))
        finally:
            if os.path.exists(img_path): os.unlink(img_path)
            if os.path.exists(th_path): os.unlink(th_path)


class TestCandidateRanking(unittest.TestCase):
    def test_apple_touch_icon_is_not_an_avatar(self):
        """The site's own icon is square and used to outrank og:image and the real avatar."""
        doc = ('<html><head>'
               '<link rel="apple-touch-icon" href="https://site.example/static/apple-touch-icon-180.png">'
               '<meta property="og:image" content="https://cdn.site.example/u/1/photo_640.jpg">'
               '</head><body>'
               '<img class="ProfileAvatar-image" src="https://cdn.site.example/u/1/photo_400.jpg">'
               '</body></html>')
        c = _avatar_candidates(doc, url="https://site.example/u", site="Site", user="u")
        self.assertTrue(c)
        self.assertNotIn("apple-touch-icon", " ".join(c))
        self.assertIn("photo_640.jpg", c[0])
        self.assertTrue(_is_generic_avatar_url("https://x/static/apple-touch-icon-180.png"))

    def test_link_rel_image_src_still_works(self):
        c = _avatar_candidates('<link rel="image_src" href="https://cdn.x/u/9/p.jpg">', url="https://x/u")
        self.assertEqual(c, ["https://cdn.x/u/9/p.jpg"])


class TestRegistrableHost(unittest.TestCase):
    def test_cc_sld_hosts_stay_distinct(self):
        """foo.co.uk and bar.co.uk both collapsed to co.uk, so the cross-platform photo
        gate treated unrelated sites as one platform and rejected real evidence."""
        self.assertEqual(_host("https://foo.co.uk/a"), "foo.co.uk")
        self.assertEqual(_host("https://bar.co.uk/a"), "bar.co.uk")
        self.assertEqual(_host("https://x.com.tr/a"), "x.com.tr")

    def test_ordinary_hosts_still_collapse_to_the_registrable_domain(self):
        self.assertEqual(_host("https://gist.github.com/a"), "github.com")
        self.assertEqual(_host("https://www.github.com/a"), "github.com")
        self.assertEqual(_host("https://a.b.example.org/x"), "example.org")
        self.assertEqual(_host("https://t.me/a"), "t.me")


if __name__ == "__main__":
    unittest.main()
