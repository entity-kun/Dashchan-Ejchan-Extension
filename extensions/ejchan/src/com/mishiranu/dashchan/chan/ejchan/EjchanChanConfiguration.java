package com.mishiranu.dashchan.chan.ejchan;

import chan.content.ChanConfiguration;

public class EjchanChanConfiguration extends ChanConfiguration {
	public static final String CAPTCHA_TYPE_EJCHAN = "ejchan_captcha";

	public EjchanChanConfiguration() {
		setDefaultName("Аноним");
		request(OPTION_ALLOW_CAPTCHA_PASS);
		addCaptchaType(CAPTCHA_TYPE_EJCHAN);
	}

	@Override
	public Board obtainBoardConfiguration(String boardName) {
		Board board = new Board();
		board.allowCatalog = true;
		board.allowPosting = true;
		board.allowReporting = true;
		return board;
	}

	@Override
	public Captcha obtainCustomCaptchaConfiguration(String captchaType) {
		if (CAPTCHA_TYPE_EJCHAN.equals(captchaType)) {
			Captcha captcha = new Captcha();
			captcha.title = getResources().getString(R.string.captcha_title);
			captcha.input = Captcha.Input.ALL;
			captcha.validity = Captcha.Validity.SHORT_LIFETIME;
			captcha.ttl = 120;
			return captcha;
		}
		return null;
	}

	@Override
	public Posting obtainPostingConfiguration(String boardName, boolean newThread) {
		Posting posting = new Posting();
		posting.allowName = true;
		posting.allowTripcode = true;
		posting.allowEmail = true;
		posting.allowSubject = newThread;
		posting.optionSage = true;
		posting.optionOriginalPoster = true;
		posting.maxCommentLength = 20000;
		posting.maxCommentLengthEncoding = "UTF-8";
		posting.attachmentCount = 4;
		posting.attachmentMimeTypes.add("image/jpeg");
		posting.attachmentMimeTypes.add("image/png");
		posting.attachmentMimeTypes.add("image/gif");
		posting.attachmentMimeTypes.add("image/webp");
		posting.attachmentMimeTypes.add("video/webm");
		posting.attachmentMimeTypes.add("video/mp4");
		posting.attachmentMimeTypes.add("audio/mpeg");
		return posting;
	}

	@Override
	public Reporting obtainReportingConfiguration(String boardName) {
		Reporting reporting = new Reporting();
		reporting.comment = true;
		return reporting;
	}

	@Override
	public Authorization obtainCaptchaPassConfiguration() {
		Authorization authorization = new Authorization();
		authorization.fieldsCount = 1;
		authorization.hints = new String[] {getResources().getString(R.string.epass_hint)};
		return authorization;
	}
}
