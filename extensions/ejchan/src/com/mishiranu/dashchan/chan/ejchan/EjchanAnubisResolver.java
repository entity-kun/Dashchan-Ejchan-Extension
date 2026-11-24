package com.mishiranu.dashchan.chan.ejchan;

import android.net.Uri;
import chan.http.CookieBuilder;
import chan.http.FirewallResolver;
import chan.http.HttpException;
import chan.http.HttpResponse;
import chan.util.StringUtils;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public class EjchanAnubisResolver extends FirewallResolver {
	private static final String SITE_HOST = "ejchan.site";
	private static final String COOKIE_STORAGE_KEY = "ejchan_anubis";
	private static final String ANUBIS_PATH = "/.within.website/";
	private static final int MAX_CHALLENGE_BYTES = 512 * 1024;

	private static boolean isCanonicalSiteUri(Uri uri) {
		return uri != null && SITE_HOST.equalsIgnoreCase(uri.getHost())
				&& "https".equalsIgnoreCase(uri.getScheme()) && (uri.getPort() == -1 || uri.getPort() == 443);
	}

	private static String getHeader(HttpResponse response, String name) {
		for (Map.Entry<String, List<String>> entry : response.getHeaderFields().entrySet()) {
			if (entry.getKey() != null && name.equalsIgnoreCase(entry.getKey())
					&& entry.getValue() != null && !entry.getValue().isEmpty()) {
				return entry.getValue().get(0);
			}
		}
		return null;
	}

	private static String readChallenge(HttpResponse response) throws HttpException {
		String contentLength = getHeader(response, "Content-Length");
		if (!StringUtils.isEmpty(contentLength)) {
			try {
				if (Long.parseLong(contentLength) > MAX_CHALLENGE_BYTES) return null;
			} catch (NumberFormatException e) {
				return null;
			}
		}
		try (InputStream input = response.open(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
			byte[] buffer = new byte[8192];
			int total = 0;
			int count;
			while ((count = input.read(buffer)) >= 0) {
				total += count;
				if (total > MAX_CHALLENGE_BYTES) return null;
				output.write(buffer, 0, count);
			}
			return new String(output.toByteArray(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw response.fail(e);
		}
	}

	private static class WebViewClient extends FirewallResolver.WebViewClient<String> {
		public WebViewClient() {
			super("Anubis");
		}

		@Override
		public boolean onPageFinished(Uri uri, Map<String, String> cookies, String title) {
			String cookie = EjchanAnubisSupport.collectCookies(cookies);
			if (!StringUtils.isEmpty(cookie)) {
				setResult(cookie);
				return true;
			}
			return false;
		}

		@Override
		public boolean onLoad(Uri initialUri, Uri uri) {
			if (!isCanonicalSiteUri(initialUri) || !isCanonicalSiteUri(uri)
					|| !Objects.equals(initialUri.getHost(), uri.getHost())
					|| !"/".equals(StringUtils.emptyIfNull(initialUri.getPath()))) return false;
			String path = StringUtils.emptyIfNull(uri.getPath());
			return path.equals("/") || path.startsWith(ANUBIS_PATH);
		}
	}

	private static class Exclusive implements FirewallResolver.Exclusive {
		@Override
		public boolean resolve(Session session, Key key) throws CancelException, InterruptedException {
			String cookie = session.resolveWebView(new WebViewClient());
			if (StringUtils.isEmpty(cookie)) return false;
			String host = StringUtils.emptyIfNull(session.getUri().getHost()).toLowerCase(Locale.US);
			EjchanChanConfiguration configuration = session.getChanConfiguration();
			configuration.storeCookie(key.formatKey(getStorageKey(host)), cookie,
					key.formatTitle("Anubis (Ejchan)"));
			return true;
		}
	}

	private static String getStorageKey(String host) {
		return COOKIE_STORAGE_KEY + "_" + StringUtils.emptyIfNull(host).toLowerCase(Locale.US);
	}

	private static Exclusive.Key toKey(Session session) {
		return session.getKey(Identifier.Flag.USER_AGENT);
	}

	@Override
	public CheckResponseResult checkResponse(Session session, HttpResponse response) throws HttpException {
		Uri uri = session.getUri();
		if (!isCanonicalSiteUri(uri) || !"/".equals(StringUtils.emptyIfNull(uri.getPath()))) return null;
		String contentType = getHeader(response, "Content-Type");
		if (response.getResponseCode() == 403 || contentType == null
				|| contentType.toLowerCase(Locale.US).contains("html")) {
			String responseText = readChallenge(response);
			if (EjchanAnubisSupport.isRussiaOnly(responseText)) {
				throw new HttpException(0, session.<EjchanChanConfiguration>getChanConfiguration().getResources()
						.getString(R.string.site_russia_only));
			}
			if (EjchanAnubisSupport.isChallenge(contentType, responseText)) {
				return new CheckResponseResult(toKey(session), new Exclusive()).setRetransmitOnSuccess(true);
			}
		}
		return null;
	}

	@Override
	public void collectCookies(Session session, CookieBuilder cookieBuilder) {
		Uri uri = session.getUri();
		if (!isCanonicalSiteUri(uri)) return;
		String host = StringUtils.emptyIfNull(uri.getHost()).toLowerCase(Locale.US);
		String cookie = session.getChanConfiguration().getCookie(toKey(session).formatKey(getStorageKey(host)));
		if (!StringUtils.isEmpty(cookie)) {
			for (String part : cookie.split(";\\s*")) {
				String[] keyValue = part.split("=", 2);
				if (keyValue.length == 2 && !StringUtils.isEmpty(keyValue[0]) && !StringUtils.isEmpty(keyValue[1])) {
					cookieBuilder.append(keyValue[0], keyValue[1]);
				}
			}
		}
	}
}
