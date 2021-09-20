package com.ez.hana.vo;

/**
 * @author HP
 *
 */
public class TranslatorVO {

	int tid;
	String applicantId;
	String motherLang;
	String firstName;
	String lastName;
	String tel1;
	String tel2;
	String tel3;
	String email;
	String branch;
	String lang;
	String langLv;
	String message;
	String fileName;
	String regDate;
	String status;

	public int getTid() {
		return tid;
	}

	public void setTid(int tid) {
		this.tid = tid;
	}

	public String getApplicantId() {
		return applicantId;
	}

	public void setApplicantId(String applicantId) {
		this.applicantId = applicantId;
	}

	public String getMotherLang() {
		return motherLang;
	}

	public void setMotherLang(String motherLang) {
		this.motherLang = motherLang;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getTel1() {
		return tel1;
	}

	public void setTel1(String tel1) {
		this.tel1 = tel1;
	}

	public String getTel2() {
		return tel2;
	}

	public void setTel2(String tel2) {
		this.tel2 = tel2;
	}

	public String getTel3() {
		return tel3;
	}

	public void setTel3(String tel3) {
		this.tel3 = tel3;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getBranch() {
		return branch;
	}

	public void setBranch(String branch) {
		this.branch = branch;
	}

	public String getLang() {
		return lang;
	}

	public void setLang(String lang) {
		this.lang = lang;
	}

	public String getLangLv() {
		return langLv;
	}

	public void setLangLv(String langLv) {
		this.langLv = langLv;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public String getRegDate() {
		return regDate;
	}

	public void setRegDate(String regDate) {
		this.regDate = regDate;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	@Override
	public String toString() {
		return "TranslatorVO [tid=" + tid + ", applicantId=" + applicantId + ", motherLang=" + motherLang
				+ ", firstName=" + firstName + ", lastName=" + lastName + ", tel1=" + tel1 + ", tel2=" + tel2
				+ ", tel3=" + tel3 + ", email=" + email + ", branch=" + branch + ", lang=" + lang + ", langLv=" + langLv
				+ ", message=" + message + ", fileName=" + fileName + ", regDate=" + regDate + ", status=" + status
				+ "]";
	}

}
