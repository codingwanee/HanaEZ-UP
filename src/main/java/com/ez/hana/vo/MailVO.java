package com.ez.hana.vo;

public class MailVO {
	private String senderName; // 발신자 이름
	private String mailFrom; // 발신자 이메일 주소
	private String mailTo; // 수신자 이메일 주소
	private String subject; // 제목
	private String content; // 본문

	public String getSenderName() {
		return senderName;
	}

	public void setSenderName(String senderName) {
		this.senderName = senderName;
	}

	public String getMailFrom() {
		return mailFrom;
	}

	public void setMailFrom(String mailFrom) {
		this.mailFrom = mailFrom;
	}

	public String getMailTo() {
		return mailTo;
	}

	public void setMailTo(String mailTo) {
		this.mailTo = mailTo;
	}

	public String getSubject() {
		return subject;
	}

	public void setSubject(String subject) {
		this.subject = subject;
	}

	public String getContent() {
		return content;
	}

	public void setContent(String content) {
		this.content = content;
	}

	@Override
	public String toString() {
		return "MailVO [senderName=" + senderName + ", mailFrom=" + mailFrom + ", mailTo=" + mailTo + ", subject="
				+ subject + ", content=" + content + "]";
	}

}
