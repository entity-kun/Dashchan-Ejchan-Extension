from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

EXT = Path(__file__).resolve().parents[1]
SRC = EXT / "src" / "com" / "mishiranu" / "dashchan" / "chan" / "ejchan"


class EjchanExtensionContractTest(unittest.TestCase):
    def test_module_declares_both_selectable_domains(self):
        build = (EXT / "build.gradle").read_text()
        locator = (SRC / "EjchanChanLocator.java").read_text()
        self.assertIn("hosts 'ejchan.site', 'ejchan.net'", build)
        self.assertIn('addChanHost("ejchan.site")', locator)
        self.assertIn('addChanHost("ejchan.net")', locator)
        self.assertIn("HttpsMode.HTTPS_ONLY", locator)

    def test_module_exposes_epass_as_captcha_pass(self):
        configuration = (SRC / "EjchanChanConfiguration.java").read_text()
        performer = (SRC / "EjchanChanPerformer.java").read_text()
        locator = (SRC / "EjchanChanLocator.java").read_text()
        self.assertIn("OPTION_ALLOW_CAPTCHA_PASS", configuration)
        self.assertIn("obtainCaptchaPassConfiguration", configuration)
        self.assertIn('buildPath("_epass")', locator)
        self.assertIn('buildPath("_csrf")', locator)
        self.assertIn('entity.add("shortcode", code)', performer)

    def test_module_uses_current_ejchan_next_api(self):
        locator = (SRC / "EjchanChanLocator.java").read_text()
        performer = (SRC / "EjchanChanPerformer.java").read_text()
        self.assertIn('buildPath("_boards")', locator)
        self.assertIn('buildPath("_captcha")', locator)
        self.assertIn('buildPath("post.php")', locator)
        self.assertNotIn("boards.json", locator)
        self.assertNotIn("inc/captcha/entrypoint.php", locator)
        self.assertIn('entity.add("csrf_token"', performer)
        self.assertIn('attachment.addToEntity(entity, "file[]")', performer)

    def test_integer_flags_from_live_json_are_not_read_as_json_booleans(self):
        mapper = (SRC / "EjchanModelMapper.java").read_text()
        for field in ("sticky", "locked", "cyclical", "archived"):
            self.assertIn(f'case "{field}"', mapper)
        self.assertIn("reader.nextInt() != 0", mapper)
    def test_epass_state_is_host_scoped_validated_and_exactly_named(self):
        performer = (SRC / "EjchanChanPerformer.java").read_text()
        self.assertIn('COOKIE_EPASS = "ejnext_epass"', performer)
        self.assertIn("getEpassStorageKey(host)", performer)
        self.assertIn("validateStoredEpass", performer)
        self.assertNotIn("lastEpassCode", performer)
        self.assertNotIn("extractEpassCookie", performer)
        self.assertNotIn("if (StringUtils.isEmpty(cookie)) cookie = getStoredEpassCookie()", performer)

    def test_json_and_captcha_allocations_are_bounded_and_bom_is_stripped(self):
        performer = (SRC / "EjchanChanPerformer.java").read_text()
        self.assertIn("MAX_JSON_BYTES", performer)
        self.assertIn("MAX_CAPTCHA_BYTES", performer)
        self.assertIn("inJustDecodeBounds", performer)
        self.assertIn("Arrays.copyOfRange(bytes, 3, bytes.length)", performer)

    def test_closed_and_locked_flags_are_combined(self):
        mapper = (SRC / "EjchanModelMapper.java").read_text()
        self.assertIn("boolean closed = false", mapper)
        self.assertIn("closed |= reader.nextInt() != 0", mapper)
        self.assertIn("post.setClosed(closed)", mapper)
    def test_epass_host_is_captured_for_the_whole_network_flow(self):
        performer = (SRC / "EjchanChanPerformer.java").read_text()
        self.assertIn("String host = getCurrentHost()", performer)
        self.assertIn("readCsrf(preset, host)", performer)
        self.assertIn("storeEpassCookie(response, host)", performer)
        self.assertIn("validateStoredEpass(preset, host)", performer)
        self.assertIn("buildPathWithHost(host, \"_epass\")", performer)

    def test_all_common_cookie_deletion_forms_are_rejected(self):
        performer = (SRC / "EjchanChanPerformer.java").read_text()
        self.assertIn('Max-Age=(-?\\\\d+)', performer)
        self.assertIn("EXPIRES_PATTERN", performer)
        self.assertIn("expires <= System.currentTimeMillis()", performer)
    def test_epass_only_posting_state_has_a_dedicated_error(self):
        performer = (SRC / "EjchanChanPerformer.java").read_text()
        strings = (EXT / "res" / "values-ru" / "strings.xml").read_text()
        self.assertIn("isEpassRequiredError", performer)
        self.assertIn('lower.contains("without")', performer)
        self.assertIn('lower.contains("disabled")', performer)
        self.assertIn("R.string.epass_required", performer)
        self.assertIn('name="epass_required"', strings)

    def test_ejchan_site_uses_anubis_root_webview_and_refreshes_cookies(self):
        performer = (SRC / "EjchanChanPerformer.java").read_text()
        resolver = (SRC / "EjchanAnubisResolver.java").read_text()
        strings = (EXT / "res" / "values-ru" / "strings.xml").read_text()
        self.assertIn("registerFirewallResolver(new EjchanAnubisResolver())", performer)
        self.assertIn("ensureSiteAccess(uri, preset)", performer)
        self.assertIn('buildPathWithHost(SITE_HOST)', performer)
        self.assertIn('.path("/").build()', performer)
        self.assertIn('SITE_HOST.equalsIgnoreCase(uri.getHost())', resolver)
        self.assertIn('"https".equalsIgnoreCase(uri.getScheme())', resolver)
        self.assertIn("uri.getPort() == -1 || uri.getPort() == 443", resolver)
        self.assertIn('"/".equals(StringUtils.emptyIfNull(uri.getPath()))', resolver)
        self.assertIn("EjchanAnubisSupport.isRussiaOnly(responseText)", resolver)
        self.assertIn("session.resolveWebView(new WebViewClient())", resolver)
        self.assertIn("setRetransmitOnSuccess(true)", resolver)
        self.assertIn('path.equals("/")', resolver)
        self.assertIn('name="site_russia_only"', strings)

    def test_anubis_cookie_and_challenge_classifier_behavior(self):
        helper = SRC / "EjchanAnubisSupport.java"
        self.assertTrue(helper.is_file())
        harness = textwrap.dedent("""
            package com.mishiranu.dashchan.chan.ejchan;
            import java.util.LinkedHashMap;
            import java.util.Map;

            public class AnubisHarness {
                private static void require(boolean value, String message) {
                    if (!value) throw new AssertionError(message);
                }

                public static void main(String[] args) {
                    Map<String, String> cookies = new LinkedHashMap<>();
                    cookies.put("unrelated", "secret");
                    cookies.put("techaro.lol-anubis-cookie-verification", "pending");
                    cookies.put("evil-anubis-auth", "attacker");
                    require(EjchanAnubisSupport.collectCookies(cookies) == null,
                            "unrecognized Anubis-like cookie must not authorize");
                    cookies.put("techaro.lol-anubis-auth-a1b2c3d4", "proof");
                    String result = EjchanAnubisSupport.collectCookies(cookies);
                    require(result.contains("techaro.lol-anubis-auth-a1b2c3d4=proof"), "auth cookie missing");
                    require(result.contains("techaro.lol-anubis-cookie-verification=pending"),
                            "verification cookie missing");
                    require(!result.contains("unrelated"), "unrelated cookie leaked");
                    require(EjchanAnubisSupport.isChallenge("text/html",
                            "<script src='/.within.website/x/x.js'></script>"), "challenge not detected");
                    require(!EjchanAnubisSupport.isChallenge("text/plain",
                            "Этот домен только для российских адресов"), "geo block misclassified");
                    require(EjchanAnubisSupport.isRussiaOnly("Этот домен только для российских адресов."),
                            "Russia-only response not detected");
                }
            }
        """)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "com" / "mishiranu" / "dashchan" / "chan" / "ejchan"
            package.mkdir(parents=True)
            harness_file = package / "AnubisHarness.java"
            harness_file.write_text(harness)
            subprocess.run(["/opt/jdk-11/bin/javac", "-d", str(root), str(helper), str(harness_file)], check=True)
            subprocess.run(["/opt/jdk-11/bin/java", "-cp", str(root),
                            "com.mishiranu.dashchan.chan.ejchan.AnubisHarness"], check=True)

    def test_official_ejchan_logo_is_packaged_as_outline_vector(self):
        icon = EXT / "res" / "drawable-v21" / "ic_custom_ejchan.xml"
        self.assertTrue(icon.is_file())
        source = icon.read_text()
        self.assertIn('android:fillColor="@android:color/transparent"', source)
        self.assertIn('android:strokeColor="#ffffffff"', source)
        self.assertIn('android:strokeWidth="8"', source)
        self.assertFalse((EXT / "res" / "drawable" / "ic_custom_ejchan.png").exists())


if __name__ == "__main__":
    unittest.main()
