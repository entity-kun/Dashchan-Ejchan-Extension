package com.mishiranu.dashchan.chan.ejchan;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.util.Base64;
import chan.content.ApiException;
import chan.content.ChanPerformer;
import chan.content.InvalidResponseException;
import chan.content.model.Board;
import chan.content.model.BoardCategory;
import chan.content.model.Post;
import chan.content.model.Posts;
import chan.http.HttpException;
import chan.http.HttpRequest;
import chan.http.HttpResponse;
import chan.http.HttpValidator;
import chan.http.MultipartEntity;
import chan.text.JsonSerial;
import chan.text.ParseException;
import chan.util.CommonUtils;
import chan.util.StringUtils;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class EjchanChanPerformer extends ChanPerformer {
	private static final String SITE_HOST = "ejchan.site";
	private static final String COOKIE_CSRF = "ejnext_csrf";
	private static final String COOKIE_EPASS = "ejnext_epass";
	private static final String COOKIE_EPASS_STORAGE = "ejchan_epass_cookie";
	private static final String COOKIE_EPASS_EXPIRY = "ejchan_epass_expiry";
	private static final String CAPTCHA_DATA_EPASS = "ejchanEpass";
	private static final int API_READ_TIMEOUT = 60000;
	private static final int MAX_JSON_BYTES = 4 * 1024 * 1024;
	private static final int MAX_CAPTCHA_BYTES = 2 * 1024 * 1024;
	private static final int MAX_CAPTCHA_DIMENSION = 2048;
	private static final long DEFAULT_EPASS_TTL = 12L * 60L * 60L * 1000L;
	private static final Pattern MAX_AGE_PATTERN = Pattern.compile("(?:^|;)\\s*Max-Age=(-?\\d+)", Pattern.CASE_INSENSITIVE);
	private static final Pattern EXPIRES_PATTERN = Pattern.compile("(?:^|;)\\s*Expires=([^;]+)", Pattern.CASE_INSENSITIVE);
	private static final int JSON_OBJECT = '{';
	private static final int JSON_ARRAY = '[';

	private static class CsrfData {
		public final String token;
		public final String cookie;

		public CsrfData(String token, String cookie) {
			this.token = token;
			this.cookie = cookie;
		}
	}

	public EjchanChanPerformer() {
		try {
			registerFirewallResolver(new EjchanAnubisResolver());
		} catch (LinkageError e) {
			e.printStackTrace();
		}
	}

	private static String readSiteError(HttpResponse response) throws HttpException {
		final int maxBytes = 64 * 1024;
		try (InputStream input = response.open(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
			byte[] buffer = new byte[4096];
			int total = 0;
			int count;
			while ((count = input.read(buffer)) >= 0) {
				int remaining = maxBytes - total;
				if (remaining <= 0) break;
				int write = Math.min(count, remaining);
				output.write(buffer, 0, write);
				total += write;
				if (write < count) break;
			}
			return new String(output.toByteArray(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw response.fail(e);
		}
	}

	private void ensureSiteAccess(Uri uri, HttpRequest.Preset preset) throws HttpException {
		if (uri == null || !SITE_HOST.equalsIgnoreCase(uri.getHost())) return;
		Uri root = EjchanChanLocator.get(this).buildPathWithHost(SITE_HOST).buildUpon().path("/").build();
		HttpResponse response = new HttpRequest(root, preset).setTimeouts(-1, API_READ_TIMEOUT)
				.addHeader("Accept", "text/html,application/xhtml+xml")
				.addHeader("Accept-Encoding", "identity").setSuccessOnly(false).perform();
		if (response.getResponseCode() >= 400) {
			String error = readSiteError(response);
			if (EjchanAnubisSupport.isRussiaOnly(error)) {
				throw new HttpException(0, EjchanChanConfiguration.get(this).getResources()
						.getString(R.string.site_russia_only));
			}
			response.checkResponseCode();
		}
	}

	private HttpRequest createJsonRequest(Uri uri, HttpRequest.Preset preset) throws HttpException {
		ensureSiteAccess(uri, preset);
		return new HttpRequest(uri, preset).setTimeouts(-1, API_READ_TIMEOUT)
				.addHeader("Accept", "application/json").addHeader("Accept-Encoding", "identity");
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

	private byte[] readJson(HttpResponse response, int expectedRoot) throws HttpException,
			InvalidResponseException {
		String contentLength = getHeader(response, "Content-Length");
		if (!StringUtils.isEmpty(contentLength)) {
			try {
				if (Long.parseLong(contentLength) > MAX_JSON_BYTES) throw new InvalidResponseException();
			} catch (NumberFormatException e) {
				throw new InvalidResponseException(e);
			}
		}
		byte[] bytes;
		try (InputStream input = response.open(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
			byte[] buffer = new byte[8192];
			int total = 0;
			int count;
			while ((count = input.read(buffer)) >= 0) {
				total += count;
				if (total > MAX_JSON_BYTES) throw new InvalidResponseException();
				output.write(buffer, 0, count);
			}
			bytes = output.toByteArray();
		} catch (IOException e) {
			throw response.fail(e);
		}
		boolean hasBom = bytes.length >= 3 && (bytes[0] & 0xff) == 0xef && (bytes[1] & 0xff) == 0xbb
				&& (bytes[2] & 0xff) == 0xbf;
		if (hasBom) bytes = Arrays.copyOfRange(bytes, 3, bytes.length);
		int index = 0;
		while (index < bytes.length) {
			int value = bytes[index] & 0xff;
			if (value != ' ' && value != '	' && value != '\r' && value != '\n') break;
			index++;
		}
		int root = index < bytes.length ? bytes[index] & 0xff : -1;
		String contentType = getHeader(response, "Content-Type");
		boolean html = root == '<' || contentType != null
				&& contentType.toLowerCase(Locale.US).startsWith("text/html");
		if (html) throw new HttpException(0, "Ejchan returned HTML instead of API data");
		if (root != expectedRoot) throw new InvalidResponseException();
		return bytes;
	}

	private String readJsonString(HttpResponse response, int expectedRoot) throws HttpException,
			InvalidResponseException {
		return new String(readJson(response, expectedRoot), StandardCharsets.UTF_8);
	}

	private String getCurrentHost() {
		String host = EjchanChanLocator.get(this).buildPath().getHost();
		return StringUtils.emptyIfNull(host).toLowerCase(Locale.US);
	}

	private static String getEpassStorageKey(String host) {
		return COOKIE_EPASS_STORAGE + "_" + host.replace('.', '_');
	}

	private static String getEpassExpiryKey(String host) {
		return COOKIE_EPASS_EXPIRY + "_" + host.replace('.', '_');
	}

	private synchronized String getStoredEpassCookie(String host) {
		EjchanChanConfiguration configuration = EjchanChanConfiguration.get(this);
		String cookie = configuration.getCookie(getEpassStorageKey(host));
		String expiryValue = configuration.getCookie(getEpassExpiryKey(host));
		long expiry = 0;
		try {
			expiry = Long.parseLong(StringUtils.emptyIfNull(expiryValue));
		} catch (NumberFormatException e) {
			// Treat malformed state as expired.
		}
		if (StringUtils.isEmpty(cookie) || expiry <= System.currentTimeMillis()) {
			clearStoredEpassCookie(host);
			return null;
		}
		return cookie;
	}

	private synchronized void clearStoredEpassCookie(String host) {
		EjchanChanConfiguration configuration = EjchanChanConfiguration.get(this);
		configuration.storeCookie(getEpassStorageKey(host), null, null);
		configuration.storeCookie(getEpassExpiryKey(host), null, null);
	}

	private synchronized String storeEpassCookie(HttpResponse response, String host) {
		String value = response.getCookieValue(COOKIE_EPASS);
		long expiry = System.currentTimeMillis() + DEFAULT_EPASS_TTL;
		boolean found = false;
		for (Map.Entry<String, List<String>> entry : response.getHeaderFields().entrySet()) {
			if (entry.getKey() == null || !"Set-Cookie".equalsIgnoreCase(entry.getKey()) || entry.getValue() == null) {
				continue;
			}
			for (String header : entry.getValue()) {
				if (StringUtils.isEmpty(header) || !header.regionMatches(true, 0, COOKIE_EPASS + "=", 0,
						COOKIE_EPASS.length() + 1)) continue;
				found = true;
				Matcher matcher = MAX_AGE_PATTERN.matcher(header);
				boolean maxAgeFound = matcher.find();
				if (maxAgeFound) {
					try {
						long seconds = Long.parseLong(matcher.group(1));
						if (seconds <= 0) value = null;
						else expiry = System.currentTimeMillis() + Math.min(seconds, 30L * 24L * 60L * 60L) * 1000L;
					} catch (NumberFormatException e) {
						value = null;
					}
				}
				Matcher expiresMatcher = EXPIRES_PATTERN.matcher(header);
				if (!maxAgeFound && expiresMatcher.find()) {
					try {
						Date expiresDate = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US)
								.parse(expiresMatcher.group(1).trim());
						long expires = expiresDate != null ? expiresDate.getTime() : 0;
						if (expires <= System.currentTimeMillis()) value = null;
						else expiry = Math.min(expiry, expires);
					} catch (java.text.ParseException e) {
						value = null;
					}
				}
			}
		}
		if (!found || StringUtils.isEmpty(value) || "deleted".equalsIgnoreCase(value)) {
			clearStoredEpassCookie(host);
			return null;
		}
		EjchanChanConfiguration configuration = EjchanChanConfiguration.get(this);
		configuration.storeCookie(getEpassStorageKey(host), value, "E-pass (" + host + ")");
		configuration.storeCookie(getEpassExpiryKey(host), Long.toString(expiry), null);
		return value;
	}

	private HttpRequest addSessionCookies(HttpRequest request, String csrfCookie, String host) {
		String epassCookie = getStoredEpassCookie(host);
		if (!StringUtils.isEmpty(epassCookie)) request.addCookie(COOKIE_EPASS, epassCookie);
		if (!StringUtils.isEmpty(csrfCookie)) request.addCookie(COOKIE_CSRF, csrfCookie);
		return request;
	}

	private CsrfData readCsrf(HttpRequest.Preset preset, String host) throws HttpException, InvalidResponseException {
		EjchanChanLocator locator = EjchanChanLocator.get(this);
		Uri uri = locator.buildPathWithHost(host, "_csrf");
		HttpResponse response = addSessionCookies(createJsonRequest(uri, preset), null, host).perform();
		try {
			JSONObject object = new JSONObject(readJsonString(response, JSON_OBJECT));
			String token = CommonUtils.optJsonString(object, "token");
			String cookie = response.getCookieValue(COOKIE_CSRF);
			if (StringUtils.isEmpty(token) || StringUtils.isEmpty(cookie)) throw new InvalidResponseException();
			return new CsrfData(token, cookie);
		} catch (JSONException e) {
			throw new InvalidResponseException(e);
		}
	}

	private synchronized String validateStoredEpass(HttpRequest.Preset preset, String host) throws HttpException,
			InvalidResponseException {
		String cookie = getStoredEpassCookie(host);
		if (StringUtils.isEmpty(cookie)) return null;
		EjchanChanLocator locator = EjchanChanLocator.get(this);
		HttpResponse response = createJsonRequest(locator.buildPathWithHost(host, "_epass"), preset)
				.addCookie(COOKIE_EPASS, cookie).perform();
		try {
			JSONObject object = new JSONObject(readJsonString(response, JSON_OBJECT));
			if (object.optBoolean("applied")) return cookie;
			clearStoredEpassCookie(host);
			return null;
		} catch (JSONException e) {
			throw new InvalidResponseException(e);
		}
	}

	@Override
	public ReadBoardsResult onReadBoards(ReadBoardsData data) throws HttpException, InvalidResponseException {
		EjchanChanLocator locator = EjchanChanLocator.get(this);
		try {
			JSONObject root = new JSONObject(readJsonString(
					createJsonRequest(locator.createBoardsApiUri(), data).perform(), JSON_OBJECT));
			JSONArray array = root.optJSONArray("boards");
			if (array == null) throw new InvalidResponseException();
			ArrayList<Board> boards = new ArrayList<>();
			for (int i = 0; i < array.length(); i++) {
				JSONObject object = array.getJSONObject(i);
				String boardName = CommonUtils.optJsonString(object, "board");
				String title = CommonUtils.optJsonString(object, "title");
				String subtitle = CommonUtils.optJsonString(object, "subtitle");
				if (!StringUtils.isEmpty(boardName) && !StringUtils.isEmpty(title)) {
					boards.add(new Board(boardName, StringUtils.clearHtml(title),
							StringUtils.nullIfEmpty(StringUtils.clearHtml(subtitle))));
				}
			}
			Collections.sort(boards);
			String category = EjchanChanConfiguration.get(this).getResources().getString(R.string.boards_title);
			return new ReadBoardsResult(new BoardCategory(category, boards));
		} catch (JSONException e) {
			throw new InvalidResponseException(e);
		}
	}

	@Override
	public ReadThreadsResult onReadThreads(ReadThreadsData data) throws HttpException, InvalidResponseException {
		EjchanChanLocator locator = EjchanChanLocator.get(this);
		Uri uri = locator.createThreadsApiUri(data.boardName, data.pageNumber, data.isCatalog());
		HttpResponse response = createJsonRequest(uri, data).setValidator(data.validator).perform();
		HttpValidator validator = response.getValidator();
		ArrayList<Posts> threads = new ArrayList<>();
		byte[] bytes = readJson(response, data.isCatalog() ? JSON_ARRAY : JSON_OBJECT);
		try (InputStream input = new ByteArrayInputStream(bytes); JsonSerial.Reader reader = JsonSerial.reader(input)) {
			if (data.isCatalog()) {
				reader.startArray();
				while (!reader.endStruct()) {
					reader.startObject();
					while (!reader.endStruct()) {
						if ("threads".equals(reader.nextName())) {
							reader.startArray();
							while (!reader.endStruct()) {
								threads.add(EjchanModelMapper.createThread(reader, locator, data.boardName, true));
							}
						} else reader.skip();
					}
				}
			} else {
				reader.startObject();
				while (!reader.endStruct()) {
					if ("threads".equals(reader.nextName())) {
						reader.startArray();
						while (!reader.endStruct()) {
							threads.add(EjchanModelMapper.createThread(reader, locator, data.boardName, false));
						}
					} else reader.skip();
				}
			}
			return new ReadThreadsResult(threads).setValidator(validator);
		} catch (ParseException e) {
			throw new InvalidResponseException(e);
		} catch (IOException e) {
			throw response.fail(e);
		}
	}

	@Override
	public ReadPostsResult onReadPosts(ReadPostsData data) throws HttpException, InvalidResponseException {
		EjchanChanLocator locator = EjchanChanLocator.get(this);
		HttpResponse response = createJsonRequest(locator.createThreadApiUri(data.boardName, data.threadNumber), data)
				.setValidator(data.validator).perform();
		ArrayList<Post> posts = new ArrayList<>();
		byte[] bytes = readJson(response, JSON_OBJECT);
		try (InputStream input = new ByteArrayInputStream(bytes); JsonSerial.Reader reader = JsonSerial.reader(input)) {
			reader.startObject();
			while (!reader.endStruct()) {
				if ("posts".equals(reader.nextName())) {
					reader.startArray();
					while (!reader.endStruct()) posts.add(EjchanModelMapper.createPost(reader, locator,
							data.boardName, null));
				} else reader.skip();
			}
			return new ReadPostsResult(new Posts(posts)).setValidator(response.getValidator()).setFullThread(true);
		} catch (ParseException e) {
			throw new InvalidResponseException(e);
		} catch (IOException e) {
			throw response.fail(e);
		}
	}

	private synchronized String verifyEpass(HttpRequest.Preset preset, String code) throws HttpException,
			InvalidResponseException {
		String host = getCurrentHost();
		if (StringUtils.isEmpty(code)) return validateStoredEpass(preset, host);
		EjchanChanLocator locator = EjchanChanLocator.get(this);
		CsrfData csrf = readCsrf(preset, host);
		MultipartEntity entity = new MultipartEntity();
		entity.add("action", "set");
		entity.add("shortcode", code);
		entity.add("csrf_token", csrf.token);
		HttpResponse response = addSessionCookies(createJsonRequest(locator.buildPathWithHost(host, "_epass"), preset),
				csrf.cookie, host).setPostMethod(entity).setSuccessOnly(false).perform();
		try {
			JSONObject object = new JSONObject(readJsonString(response, JSON_OBJECT));
			if (object.optBoolean("applied")) return storeEpassCookie(response, host);
			clearStoredEpassCookie(host);
			return null;
		} catch (JSONException e) {
			throw new InvalidResponseException(e);
		}
	}

	@Override
	public CheckAuthorizationResult onCheckAuthorization(CheckAuthorizationData data) throws HttpException,
			InvalidResponseException {
		String code = data.authorizationData != null && data.authorizationData.length > 0
				? data.authorizationData[0] : null;
		if (StringUtils.isEmpty(code)) {
			clearStoredEpassCookie(getCurrentHost());
			return new CheckAuthorizationResult(false);
		}
		return new CheckAuthorizationResult(verifyEpass(data, code) != null);
	}

	private static ReadCaptchaResult createEpassResult(String cookie) {
		CaptchaData captchaData = new CaptchaData();
		captchaData.put(CAPTCHA_DATA_EPASS, cookie);
		return new ReadCaptchaResult(CaptchaState.PASS, captchaData)
				.setValidity(EjchanChanConfiguration.Captcha.Validity.LONG_LIFETIME);
	}

	@Override
	public ReadCaptchaResult onReadCaptcha(ReadCaptchaData data) throws HttpException, InvalidResponseException {
		String code = data.captchaPass != null && data.captchaPass.length > 0 ? data.captchaPass[0] : null;
		String epassCookie = verifyEpass(data, code);
		if (!StringUtils.isEmpty(epassCookie)) return createEpassResult(epassCookie);
		EjchanChanLocator locator = EjchanChanLocator.get(this);
		String host = getCurrentHost();
		try {
			Uri configUri = locator.buildQueryWithHost(host, "_config", "board", data.boardName);
			JSONObject config = new JSONObject(readJsonString(
					createJsonRequest(configUri, data).perform(), JSON_OBJECT));
			if (!config.optBoolean("captcha_enabled", true)) {
				return new ReadCaptchaResult(CaptchaState.SKIP, null);
			}
		} catch (JSONException e) {
			throw new InvalidResponseException(e);
		}
		if (data.mayShowLoadButton) return new ReadCaptchaResult(CaptchaState.NEED_LOAD, null);
		try {
			Uri captchaUri = locator.buildPathWithHost(host, "_captcha");
			JSONObject object = new JSONObject(readJsonString(
					addSessionCookies(createJsonRequest(captchaUri, data), null, host).perform(), JSON_OBJECT));
			if (object.optBoolean("trusted")) return new ReadCaptchaResult(CaptchaState.SKIP, null);
			String cookie = CommonUtils.optJsonString(object, "cookie");
			String image = CommonUtils.optJsonString(object, "image");
			int comma = image != null ? image.indexOf(',') : -1;
			if (StringUtils.isEmpty(cookie) || comma < 0 || image.length() - comma - 1 > MAX_CAPTCHA_BYTES * 2) {
				throw new InvalidResponseException();
			}
			byte[] bytes = Base64.decode(image.substring(comma + 1), Base64.DEFAULT);
			if (bytes.length == 0 || bytes.length > MAX_CAPTCHA_BYTES) throw new InvalidResponseException();
			BitmapFactory.Options bounds = new BitmapFactory.Options();
			bounds.inJustDecodeBounds = true;
			BitmapFactory.decodeByteArray(bytes, 0, bytes.length, bounds);
			if (bounds.outWidth <= 0 || bounds.outHeight <= 0 || bounds.outWidth > MAX_CAPTCHA_DIMENSION
					|| bounds.outHeight > MAX_CAPTCHA_DIMENSION
					|| (long) bounds.outWidth * bounds.outHeight > MAX_CAPTCHA_DIMENSION * MAX_CAPTCHA_DIMENSION) {
				throw new InvalidResponseException();
			}
			Bitmap bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
			if (bitmap == null) throw new InvalidResponseException();
			CaptchaData captchaData = new CaptchaData();
			captchaData.put(CaptchaData.CHALLENGE, cookie);
			return new ReadCaptchaResult(CaptchaState.CAPTCHA, captchaData)
					.setCaptchaType(EjchanChanConfiguration.CAPTCHA_TYPE_EJCHAN)
					.setInput(EjchanChanConfiguration.Captcha.Input.ALL)
					.setValidity(EjchanChanConfiguration.Captcha.Validity.SHORT_LIFETIME).setImage(bitmap);
		} catch (JSONException | IllegalArgumentException e) {
			throw new InvalidResponseException(e);
		}
	}

	private String solveCaptcha(HttpRequest.Preset preset, CsrfData csrf, CaptchaData captchaData, String host)
			throws HttpException, InvalidResponseException, ApiException {
		if (captchaData == null) return null;
		String epass = captchaData.get(CAPTCHA_DATA_EPASS);
		if (!StringUtils.isEmpty(epass)) return null;
		String challenge = captchaData.get(CaptchaData.CHALLENGE);
		String input = captchaData.get(CaptchaData.INPUT);
		if (StringUtils.isEmpty(challenge)) return null;
		MultipartEntity entity = new MultipartEntity();
		entity.add("csrf_token", csrf.token);
		entity.add("captcha_cookie", challenge);
		entity.add("captcha_text", StringUtils.emptyIfNull(input));
		EjchanChanLocator locator = EjchanChanLocator.get(this);
		Uri solveUri = locator.buildPathWithHost(host, "_captcha", "solve");
		HttpResponse response = addSessionCookies(createJsonRequest(solveUri, preset), csrf.cookie, host)
				.setPostMethod(entity).setSuccessOnly(false).perform();
		try {
			JSONObject object = new JSONObject(readJsonString(response, JSON_OBJECT));
			String ticket = CommonUtils.optJsonString(object, "ticket");
			if (!StringUtils.isEmpty(ticket)) return ticket;
			throw new ApiException(ApiException.SEND_ERROR_CAPTCHA);
		} catch (JSONException e) {
			throw new InvalidResponseException(e);
		}
	}

	@Override
	public SendPostResult onSendPost(SendPostData data) throws HttpException, ApiException,
			InvalidResponseException {
		EjchanChanLocator locator = EjchanChanLocator.get(this);
		String host = getCurrentHost();
		CsrfData csrf = readCsrf(data, host);
		String captchaTicket = solveCaptcha(data, csrf, data.captchaData, host);
		MultipartEntity entity = new MultipartEntity();
		entity.add("board", data.boardName);
		entity.add("thread", data.threadNumber != null ? data.threadNumber : "0");
		entity.add("name", data.name);
		if (data.optionOriginalPoster) entity.add("op", "1");
		entity.add("email", data.optionSage ? "sage" : data.email);
		if (data.threadNumber == null) entity.add("subject", data.subject);
		entity.add("body", StringUtils.emptyIfNull(data.comment));
		entity.add("csrf_token", csrf.token);
		entity.add("website", "");
		if (!StringUtils.isEmpty(captchaTicket)) entity.add("captcha_ticket", captchaTicket);
		if (data.attachments != null) {
			for (SendPostData.Attachment attachment : data.attachments) {
				attachment.addToEntity(entity, "file[]");
			}
		}
		Uri postUri = locator.buildPathWithHost(host, "post.php");
		HttpResponse response = addSessionCookies(createJsonRequest(postUri, data), csrf.cookie, host)
				.setPostMethod(entity).setSuccessOnly(false).perform();
		try {
			JSONObject object = new JSONObject(readJsonString(response, JSON_OBJECT));
			if (object.optBoolean("ok")) {
				String postNumber = CommonUtils.optJsonString(object, "id");
				if (StringUtils.isEmpty(postNumber)) throw new InvalidResponseException();
				return data.threadNumber == null ? new SendPostResult(postNumber, null)
						: new SendPostResult(data.threadNumber, postNumber);
			}
			handlePostError(CommonUtils.optJsonString(object, "error"), host);
			throw new InvalidResponseException();
		} catch (JSONException e) {
			throw new InvalidResponseException(e);
		}
	}

	private static boolean isEpassRequiredError(String lower) {
		boolean mentionsEpass = lower.contains("е-пропуск") || lower.contains("е пропуск")
				|| lower.contains("e-pass") || lower.contains("epass");
		return mentionsEpass && (lower.contains("без") || lower.contains("треб")
				|| lower.contains("отключ") || lower.contains("only") || lower.contains("required")
				|| lower.contains("without") || lower.contains("disabled"));
	}

	private void handlePostError(String message, String host) throws ApiException {
		if (StringUtils.isEmpty(message)) return;
		String clear = StringUtils.clearHtml(message);
		String lower = clear.toLowerCase(Locale.US);
		if (isEpassRequiredError(lower)) {
			clearStoredEpassCookie(host);
			throw new ApiException(EjchanChanConfiguration.get(this).getResources()
					.getString(R.string.epass_required));
		}
		int type = lower.contains("капч") || lower.contains("captcha") || lower.contains("verification")
				? ApiException.SEND_ERROR_CAPTCHA
				: lower.contains("флуд") || lower.contains("flood") || lower.contains("too fast")
				? ApiException.SEND_ERROR_TOO_FAST
				: lower.contains("закрыт") || lower.contains("locked") ? ApiException.SEND_ERROR_CLOSED
				: lower.contains("слишком большой") || lower.contains("too big") || lower.contains("file size")
				? ApiException.SEND_ERROR_FILE_TOO_BIG : 0;
		if (type == ApiException.SEND_ERROR_CAPTCHA) clearStoredEpassCookie(host);
		if (type != 0) throw new ApiException(type);
		throw new ApiException(clear);
	}

	@Override
	public SendReportPostsResult onSendReportPosts(SendReportPostsData data) throws HttpException, ApiException,
			InvalidResponseException {
		if (data.postNumbers.isEmpty()) throw new InvalidResponseException();
		EjchanChanLocator locator = EjchanChanLocator.get(this);
		String host = getCurrentHost();
		CsrfData csrf = readCsrf(data, host);
		MultipartEntity entity = new MultipartEntity();
		entity.add("board", data.boardName);
		entity.add("post", data.postNumbers.get(0));
		entity.add("reason", StringUtils.emptyIfNull(data.comment));
		entity.add("csrf_token", csrf.token);
		Uri reportUri = locator.buildPathWithHost(host, "_report");
		HttpResponse response = addSessionCookies(createJsonRequest(reportUri, data), csrf.cookie, host)
				.setPostMethod(entity).setSuccessOnly(false).perform();
		try {
			JSONObject object = new JSONObject(readJsonString(response, JSON_OBJECT));
			if (object.optBoolean("ok")) return new SendReportPostsResult();
			String error = CommonUtils.optJsonString(object, "error");
			if (!StringUtils.isEmpty(error)) throw new ApiException(StringUtils.clearHtml(error));
			throw new InvalidResponseException();
		} catch (JSONException e) {
			throw new InvalidResponseException(e);
		}
	}
}
