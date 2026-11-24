package com.mishiranu.dashchan.chan.ejchan;

import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

final class EjchanAnubisSupport {
	private static final String ANUBIS_PATH = "/.within.website/";
	private static final Pattern AUTH_COOKIE = Pattern.compile(
			"^techaro\\.lol-anubis-auth(?:-[0-9a-f]{8})?$", Pattern.CASE_INSENSITIVE);
	private static final Pattern VERIFICATION_COOKIE = Pattern.compile(
			"^techaro\\.lol-anubis-cookie-verification(?:-[0-9a-f]{8})?$", Pattern.CASE_INSENSITIVE);

	private EjchanAnubisSupport() {}

	private static boolean isAllowedCookie(String name) {
		return name != null && (AUTH_COOKIE.matcher(name).matches() || VERIFICATION_COOKIE.matcher(name).matches());
	}

	private static boolean isAuthorizationCookie(String name) {
		return name != null && AUTH_COOKIE.matcher(name).matches();
	}

	private static boolean isSafeCookieName(String name) {
		if (name == null || name.isEmpty()) return false;
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
					|| "!#$%&'*+-.^_`|~".indexOf(c) >= 0)) return false;
		}
		return true;
	}

	private static boolean isSafeCookieValue(String value) {
		if (value == null || value.isEmpty()) return false;
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (c == ';' || c == '\r' || c == '\n' || c == 0) return false;
		}
		return true;
	}

	static String collectCookies(Map<String, String> cookies) {
		if (cookies == null || cookies.isEmpty()) return null;
		StringBuilder builder = new StringBuilder();
		boolean authorized = false;
		for (Map.Entry<String, String> entry : cookies.entrySet()) {
			String name = entry.getKey();
			String value = entry.getValue();
			if (isAllowedCookie(name) && isSafeCookieName(name) && isSafeCookieValue(value)) {
				if (builder.length() > 0) builder.append("; ");
				builder.append(name).append('=').append(value);
				authorized |= isAuthorizationCookie(name);
			}
		}
		return authorized ? builder.toString() : null;
	}

	static boolean isChallenge(String contentType, String responseText) {
		if (responseText == null || responseText.isEmpty() || isRussiaOnly(responseText)) return false;
		String lower = responseText.toLowerCase(Locale.US);
		boolean marker = lower.contains(ANUBIS_PATH) || lower.contains("anubis_challenge")
				|| lower.contains("techaro.lol-anubis") || lower.contains("making sure you're not a bot");
		return marker && (contentType == null || contentType.toLowerCase(Locale.US).contains("html")
				|| lower.contains("<html") || lower.contains("<script"));
	}

	static boolean isRussiaOnly(String responseText) {
		if (responseText == null || responseText.isEmpty()) return false;
		String lower = responseText.toLowerCase(Locale.US);
		return lower.contains("только для российских адресов")
				|| lower.contains("доступен только из россии")
				|| lower.contains("only available from russian")
				|| lower.contains("only for russian ip");
	}
}
