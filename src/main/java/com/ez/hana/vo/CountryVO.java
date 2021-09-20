package com.ez.hana.vo;

/**
 * @author HP
 *
 */
public class CountryVO {

	String nameKo;
	String codeAlpha3;
	String codeAlpha2;
	String nameEn;

	public String getNameKo() {
		return nameKo;
	}

	public void setNameKo(String nameKo) {
		this.nameKo = nameKo;
	}

	public String getCodeAlpha3() {
		return codeAlpha3;
	}

	public void setCodeAlpha3(String codeAlpha3) {
		this.codeAlpha3 = codeAlpha3;
	}

	public String getCodeAlpha2() {
		return codeAlpha2;
	}

	public void setCodeAlpha2(String codeAlpha2) {
		this.codeAlpha2 = codeAlpha2;
	}

	public String getNameEn() {
		return nameEn;
	}

	public void setNameEn(String nameEn) {
		this.nameEn = nameEn;
	}

	@Override
	public String toString() {
		return "CountryVO [nameKo=" + nameKo + ", codeAlpha3=" + codeAlpha3 + ", codeAlpha2=" + codeAlpha2 + ", nameEn="
				+ nameEn + "]";
	}

}
