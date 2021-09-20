package com.ez.hana.vo;

public class BranchVO {

	private String bid;
	private String nameKo;
	private String nameEn;
	private String addrKoOld;
	private String addrKoNew;
	private String addrEn;
	private String tel;
	private String fax;
	private String post;
	private String loc;
	private String regDate;

	public String getBid() {
		return bid;
	}

	public void setBid(String bid) {
		this.bid = bid;
	}

	public String getNameKo() {
		return nameKo;
	}

	public void setNameKo(String nameKo) {
		this.nameKo = nameKo;
	}

	public String getNameEn() {
		return nameEn;
	}

	public void setNameEn(String nameEn) {
		this.nameEn = nameEn;
	}

	public String getAddrKoOld() {
		return addrKoOld;
	}

	public void setAddrKoOld(String addrKoOld) {
		this.addrKoOld = addrKoOld;
	}

	public String getAddrKoNew() {
		return addrKoNew;
	}

	public void setAddrKoNew(String addrKoNew) {
		this.addrKoNew = addrKoNew;
	}

	public String getAddrEn() {
		return addrEn;
	}

	public void setAddrEn(String addrEn) {
		this.addrEn = addrEn;
	}

	public String getTel() {
		return tel;
	}

	public void setTel(String tel) {
		this.tel = tel;
	}

	public String getFax() {
		return fax;
	}

	public void setFax(String fax) {
		this.fax = fax;
	}

	public String getPost() {
		return post;
	}

	public void setPost(String post) {
		this.post = post;
	}

	public String getLoc() {
		return loc;
	}

	public void setLoc(String loc) {
		this.loc = loc;
	}

	public String getRegDate() {
		return regDate;
	}

	public void setRegDate(String regDate) {
		this.regDate = regDate;
	}

	@Override
	public String toString() {
		return "BranchVO [bid=" + bid + ", nameKo=" + nameKo + ", nameEn=" + nameEn + ", addrKoOld=" + addrKoOld
				+ ", addrKoNew=" + addrKoNew + ", addrEn=" + addrEn + ", tel=" + tel + ", fax=" + fax + ", post=" + post
				+ ", loc=" + loc + ", regDate=" + regDate + "]";
	}

}
