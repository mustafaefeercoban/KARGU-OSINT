#!/usr/bin/env python3
"""Offline regression tests for verification, name extraction, photo grouping and the AUTO-FINDINGS rewrite.

Run: python3 tests/test_verify.py  (or: python3 -m unittest discover tests)
"""
import importlib.util
import io
import pathlib
import sys
import tempfile
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_engine():
    """Import osint_run.py by path; the project is not a package."""
    spec = importlib.util.spec_from_file_location("osint_run", ROOT / "osint_run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


O = _load_engine()


class _Resp:
    """Minimal requests.Response stand-in."""

    def __init__(self, status=200, body=b"", ctype="text/html; charset=utf-8",
                 url="https://example.com/x", encoding="utf-8"):
        self.status_code = status
        self.headers = {"content-type": ctype}
        self.url = url
        self.encoding = encoding
        self._body = body

    def iter_content(self, n):
        for i in range(0, len(self._body), n):
            yield self._body[i:i + n]

    def close(self):
        pass


def verify(html_body, user="aysegunes", status=200, ctype="text/html",
           url=None, site="Site"):
    """Run verify_account against a fixture page instead of the network."""
    url = url or f"https://example.com/{user}"
    body = html_body.encode("utf-8") if isinstance(html_body, str) else html_body
    fake = types.ModuleType("requests")
    fake.get = lambda *a, **kw: _Resp(status=status, body=body, ctype=ctype, url=url)
    real = sys.modules.get("requests")
    sys.modules["requests"] = fake
    try:
        return O.verify_account({"url": url, "user": user, "site": site, "via": ["sherlock"]},
                                fetch_avatar=False)
    finally:
        if real is not None:
            sys.modules["requests"] = real
        else:
            sys.modules.pop("requests", None)


# --------------------------------------------------------------------------- decision chain

class DecisionChain(unittest.TestCase):

    def test_consent_wall_is_not_verified(self):
        """A consent interstitial echoing the handle in its URL must not verify."""
        page = """<html><head><title>Before you continue to YouTube</title></head>
        <body><p>Before you continue, we use cookies.</p>
        <a href="https://www.youtube.com/@aysegunes">Continue to youtube.com/@aysegunes</a>
        </body></html>"""
        r = verify(page, url="https://www.youtube.com/@aysegunes")
        self.assertEqual(r["state"], "unconfirmed")
        self.assertIn("interstitial", r["note"])
        self.assertEqual(r["display_name"], "")

    def test_handle_only_in_markup_is_not_evidence(self):
        """A handle only in href, script or canonical markup is not evidence."""
        page = """<html><head><title>Some Site</title>
        <link rel="canonical" href="https://example.com/aysegunes">
        <script>var profile = "aysegunes";</script></head>
        <body><p>Nothing to see here.</p></body></html>"""
        self.assertEqual(verify(page)["state"], "unconfirmed")

    def test_style_block_unclosed_within_the_cap_does_not_leak(self):
        """A <style> left unclosed by the read cap must still be stripped from visible text."""
        page = ("<html><head><title>Some Site</title><style>"
                + ".aysegunes-grid{color:red}" * 400
                + "<body><p>nothing here</p>")   # no </style> inside the window
        r = verify(page)
        self.assertEqual(r["state"], "unconfirmed")

    def test_handle_in_visible_text_verifies(self):
        page = """<html><head><title>Some Site</title></head>
        <body><h1>@aysegunes</h1><p>42 followers</p></body></html>"""
        self.assertEqual(verify(page)["state"], "verified")

    def test_handle_in_title_verifies(self):
        page = """<html><head><title>Telegram: Contact @aysegunes</title></head>
        <body><p>You can contact this account right away.</p></body></html>"""
        self.assertEqual(verify(page)["state"], "verified")

    def test_name_with_separators_counts_as_the_handle(self):
        """The handle's human-readable name form counts as the handle."""
        page = """<html><head><title>Chess.com</title></head>
        <body><h1>Ayşe Güneş</h1><p>Rapid 1200</p></body></html>"""
        self.assertEqual(verify(page)["state"], "verified")

    def test_short_handle_does_not_match_inside_a_longer_word(self):
        """Handle matching is word-anchored, not substring."""
        page = """<html><head><title>Some Site</title></head>
        <body><p>Welcome to aysegunes's page</p></body></html>"""
        self.assertNotEqual(verify(page, user="gune")["state"], "verified")

    def test_unreadable_body_is_not_verified(self):
        """An HTTP 200 with an unreadable body never verifies."""
        r = verify(b"\x89PNG\r\n\x1a\n", ctype="image/png")
        self.assertEqual(r["state"], "unconfirmed")
        self.assertIn("non-text", r["note"])

    def test_bio_joke_does_not_kill_a_live_account(self):
        """DEAD_MARKERS are not applied to og:description (subject-authored text)."""
        page = """<html><head><title>aysegunes</title>
        <meta property="og:description" content="404: bio not found"></head>
        <body><h1>aysegunes</h1></body></html>"""
        self.assertEqual(verify(page)["state"], "verified")

    def test_dead_marker_in_title_still_means_dead(self):
        page = """<html><head><title>User not found</title></head>
        <body><p>aysegunes</p></body></html>"""
        self.assertEqual(verify(page)["state"], "dead")

    def test_status_codes(self):
        self.assertEqual(verify("<title>x</title>", status=404)["state"], "dead")
        self.assertEqual(verify("<title>x</title>", status=403)["state"], "blocked")
        self.assertEqual(verify("<title>x</title>", status=418)["state"], "unknown")


# --------------------------------------------------------------------------- name extraction

class DisplayName(unittest.TestCase):

    def name(self, title, user="aysegunes", site="Site", ogt=""):
        return O._display_name(title, ogt, user, site)

    def test_name_whose_slug_is_the_handle_is_kept(self):
        """A display name whose slug equals the handle is still a name."""
        self.assertEqual(self.name("Ayşe Güneş"), "Ayşe Güneş")

    def test_parenthesised_name_is_kept(self):
        self.assertEqual(self.name("AYŞE GÜNEŞ (gunesayse) - Pinterest",
                                   user="gunesayse", site="Pinterest"),
                         "AYŞE GÜNEŞ")

    def test_bare_handle_is_not_a_name(self):
        self.assertEqual(self.name("aysegunes"), "")

    def test_handle_with_an_at_sigil_is_not_a_name(self):
        """Only an internal separator makes a title a name; a leading @ does not."""
        self.assertEqual(self.name("@aysegunes"), "")
        self.assertEqual(self.name("@GunesAyse", user="gunesayse"), "")

    def test_handle_among_other_words_is_not_a_name(self):
        self.assertEqual(self.name("Telegram: Contact @aysegunes"), "")

    def test_consent_screen_is_not_a_name(self):
        self.assertEqual(self.name("Before you continue to YouTube"), "")

    def test_soft_404_titles_are_not_names(self):
        for junk in ("Deleted user | Reddit", "Şu kişiyi bulamadık",
                     "This account has been suspended", "Sorry, this page isn't available.",
                     "Error", "Content unavailable"):
            with self.subTest(junk=junk):
                self.assertEqual(self.name(junk, user="someuser"), "")


# --------------------------------------------------------------------------- photo grouping

FLAT = "0000000000000000"          # popcount 0  — a solid default avatar
FULL = "ffffffffffffffff"          # popcount 64 — also degenerate
A = "aaaaaaaaaaaaaaaa"             # popcount 32
A2 = "aaaaaaaaaaaaaaa0"            # 2 bits from A: the same photo re-encoded
B = "5555555555555555"             # 64 bits from A: a different picture


def acct(url, h, sha=None):
    return {"url": url, "site": url.split("/")[2], "avatar_hash": h, "avatar_sha256": sha}


class PhotoGroups(unittest.TestCase):

    def test_identical_bytes_across_platforms_is_strong(self):
        rows = [acct("https://github.com/u", A, "deadbeef"),
                acct("https://gitlab.com/u", A, "deadbeef")]
        groups = O.group_by_photo(rows)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["tier"], "strong")
        self.assertEqual(rows[0]["photo_tier"], "strong")

    def test_perceptual_match_is_only_possible(self):
        """A perceptual-only match is tiered 'possible', never 'strong'."""
        rows = [acct("https://github.com/u", A, "aaa1"),
                acct("https://gitlab.com/u", A2, "bbb2")]
        groups = O.group_by_photo(rows)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["tier"], "possible")

    def test_flat_default_avatars_never_group(self):
        """Degenerate hashes (default avatars) never form a group."""
        for h in (FLAT, FULL):
            with self.subTest(hash=h):
                rows = [acct("https://a.com/u", h, "s1"), acct("https://b.com/v", h, "s1")]
                self.assertEqual(O.group_by_photo(rows), [])
                self.assertIn("photo_note", rows[0])

    def test_same_registrable_domain_is_not_evidence(self):
        rows = [acct("https://github.com/u", A, "same"),
                acct("https://gist.github.com/u", A, "same")]
        self.assertEqual(O.group_by_photo(rows), [])

    def test_different_pictures_do_not_group(self):
        rows = [acct("https://a.com/u", A, "s1"), acct("https://b.com/v", B, "s2")]
        self.assertEqual(O.group_by_photo(rows), [])

    def test_grouping_is_order_independent(self):
        """Group membership does not depend on row order."""
        rows = [acct("https://a.com/u", A, "s1"), acct("https://b.com/v", A2, "s2"),
                acct("https://c.com/w", A, "s3")]
        self.assertEqual(len(O.group_by_photo(rows)[0]["members"]), 3)
        self.assertEqual(len(O.group_by_photo(list(reversed(rows)))[0]["members"]), 3)


# --------------------------------------------------------------------------- stats + rewrite

def _findings(states):
    ver = [{"url": f"https://s{i}.com/u", "site": f"s{i}", "user": "u", "via": ["sherlock"],
            "state": st} for i, st in enumerate(states)]
    return {"input": {"name": ["U"], "username": ["u"], "email": [], "phone": [],
                      "domain": [], "file": [], "notes": []},
            "identity": {}, "email": {}, "domain": {}, "phone": [], "metadata": [],
            "verified": ver, "did_verify": True}


class Stats(unittest.TestCase):

    def test_cards_account_for_every_row(self):
        """verified + undecided + dead + unreachable equals the row count."""
        states = ["verified", "verified", "unconfirmed", "blocked", "unknown", "dead", "error"]
        st = O._stats(_findings(states))
        self.assertEqual(st["verified"] + st["undecided"] + st["dead"] + st["unreachable"],
                         len(states))
        self.assertEqual(st["undecided"], 3)


class TargetRewrite(unittest.TestCase):

    def test_operator_notes_below_the_block_survive_a_rescan(self):
        """Text after the AUTO-FINDINGS end marker survives a rewrite."""
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "case.txt"
            p.write_text("name: U\nusername: u\n", encoding="utf-8")
            O.update_target(p, _findings(["verified"]), "20260101-000000")
            first = p.read_text(encoding="utf-8")
            self.assertIn(O.AF_END, first)

            p.write_text(first + "\nnotes: found by hand on a forum\n", encoding="utf-8")
            O.update_target(p, _findings(["verified", "dead"]), "20260102-000000")
            second = p.read_text(encoding="utf-8")

            self.assertIn("found by hand on a forum", second)
            self.assertIn("name: U", second)
            self.assertEqual(second.count(O.AF_END), 1)
            self.assertEqual(second.count("# ==== AUTO-FINDINGS ("), 1)

    def test_legacy_block_without_end_marker_is_still_replaced(self):
        """A block without an end marker is replaced, not duplicated."""
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "case.txt"
            p.write_text("name: U\n\n# ==== AUTO-FINDINGS (old) — appended by the scanner ===="
                         "\nfound_account: [verified] Old | https://old/x | user=u | ()\n",
                         encoding="utf-8")
            O.update_target(p, _findings(["verified"]), "20260103-000000")
            out = p.read_text(encoding="utf-8")
            self.assertEqual(out.count("# ==== AUTO-FINDINGS ("), 1)
            self.assertNotIn("https://old/x", out)
            self.assertIn("name: U", out)


# --------------------------------------------------------------------------- opsec hardening

class TargetParsing(unittest.TestCase):

    def _parse(self, text):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "t.txt"
            p.write_text(text, encoding="utf-8")
            return O.parse_target(p)

    def test_leading_hyphen_identifiers_are_dropped(self):
        """Identifiers become argv for external tools, so flag-like values are dropped."""
        prof = self._parse("username: --help\nusername: real_user\nemail: -x@example.com\n")
        self.assertEqual(prof["username"], ["real_user"])
        self.assertEqual(prof["email"], [])

    def test_file_expands_tilde_but_not_environment_variables(self):
        """file: paths expand ~ but never environment variables."""
        import os
        os.environ["OSINT_TEST_SECRET"] = "hunter-key-1234567890"
        prof = self._parse("file: $OSINT_TEST_SECRET\nfile: ~/photo.jpg\n")
        self.assertIn("$OSINT_TEST_SECRET", prof["file"])
        self.assertNotIn("hunter-key-1234567890", " ".join(prof["file"]))
        self.assertTrue(any(f.startswith("/") for f in prof["file"]))   # ~ expanded


class FetchGuard(unittest.TestCase):

    def test_non_http_schemes_are_refused(self):
        for u in ("javascript:alert(1)", "file:///etc/passwd", "ftp://x/y", "", None):
            with self.subTest(url=u):
                self.assertFalse(O._fetch_target_ok(u))

    def test_loopback_and_private_hosts_are_refused(self):
        """Avatar fetches never reach loopback, private or link-local hosts."""
        for u in ("http://127.0.0.1:8787/x.png", "http://localhost/x", "http://10.0.0.1/a",
                  "http://192.168.1.1/a", "http://169.254.169.254/latest/meta-data",
                  "http://[::1]/x", "http://foo.local/x"):
            with self.subTest(url=u):
                self.assertFalse(O._fetch_target_ok(u))

    def test_public_ip_literal_is_allowed(self):
        self.assertTrue(O._fetch_target_ok("https://1.1.1.1/avatar.jpg"))


class ReportEscaping(unittest.TestCase):

    def test_href_only_admits_http_schemes(self):
        self.assertEqual(O._href("javascript:alert(1)"), "#")
        self.assertEqual(O._href("data:text/html,x"), "#")
        self.assertEqual(O._href(None), "#")
        self.assertEqual(O._href("https://a.b/c?d=1&e=2"), "https://a.b/c?d=1&amp;e=2")

    def test_img_only_admits_own_jpeg_data_uris(self):
        self.assertEqual(O._img("https://evil.example/x.jpg"), "")
        self.assertEqual(O._img("data:text/html;base64,PHNjcmlwdD4="), "")
        self.assertEqual(O._img("data:image/jpeg;base64,/9j/4AAQ"), "data:image/jpeg;base64,/9j/4AAQ")
        self.assertEqual(O._img("data:image/jpeg;base64,<svg onload=x>"), "")


class AvatarCache(unittest.TestCase):

    def test_same_url_is_fetched_once_across_calls(self):
        """The same avatar URL is fetched and hashed once."""
        from PIL import Image
        buf = io.BytesIO(); Image.new("RGB", (64, 64), (120, 40, 200)).save(buf, "JPEG")
        blob = buf.getvalue()
        calls = []
        fake = types.ModuleType("requests")

        def get(url, **kw):
            calls.append(url)
            return _Resp(200, blob, "image/jpeg", url)
        fake.get = get
        real = sys.modules.get("requests"); sys.modules["requests"] = fake
        try:
            O._THUMB_CACHE.clear()
            url = "https://1.1.1.1/avatars/u.jpg"      # public IP literal: no DNS in tests
            a = O._thumb([url]); b = O._thumb([url]); c = O._thumb([url])
        finally:
            if real is not None: sys.modules["requests"] = real
            else: sys.modules.pop("requests", None)
        self.assertEqual(len(calls), 1)
        self.assertEqual(a, b); self.assertEqual(b, c)
        self.assertTrue(a[0].startswith("data:image/jpeg;base64,"))
        self.assertEqual(len(a[3]), 64)                  # sha256 hex of the original bytes


class ReportLayout(unittest.TestCase):

    def _report(self, states, opsec=None):
        f = _findings(states)
        f["opsec"] = opsec or {}
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "case.txt"; p.write_text("name: U\n")
            return O.write_html_report(f, p, "20260101-000000").read_text(encoding="utf-8")

    def test_undecided_rows_collapse_grouped_by_site(self):
        """Undecided rows are collapsed into a per-site details block."""
        f = _findings(["verified", "dead", "unconfirmed", "unconfirmed", "blocked", "unknown"])
        f["verified"][2]["site"] = f["verified"][3]["site"] = "F3.cool"
        f["opsec"] = {}
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "case.txt"; p.write_text("name: U\n")
            html = O.write_html_report(f, p, "20260101-000000").read_text(encoding="utf-8")
        self.assertIn("Undecided: 4 row(s) on 3 site(s)", html)
        self.assertIn("id='acc2'", html)
        main_table = html.split("id='acc'")[1].split("</table>")[0]
        self.assertEqual(main_table.count("<tr class="), 2)          # verified + dead only
        self.assertIn("<details>", html)

    def test_exit_change_is_reported_loudly(self):
        op = {"egress": {"ip": "1.1.1.1", "mullvad": True, "country": "RO"},
              "egress_end": {"ip": "9.9.9.9", "mullvad": False, "country": "TR"},
              "egress_changed": True, "lockdown": "off",
              "target_hosts": {}, "third_parties": {}, "tools": []}
        html = self._report(["verified"], op)
        self.assertIn("CHANGED", html)
        self.assertIn("treat this scan as exposed", html)
        self.assertIn("--no-lockdown", html)

    def test_stable_exit_is_reported_as_unchanged(self):
        op = {"egress": {"ip": "1.1.1.1", "mullvad": True, "country": "RO"},
              "egress_end": {"ip": "1.1.1.1", "mullvad": True, "country": "RO"},
              "egress_changed": False, "lockdown": "on",
              "target_hosts": {}, "third_parties": {}, "tools": []}
        html = self._report(["verified"], op)
        self.assertIn("unchanged", html)
        self.assertNotIn("CHANGED", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
