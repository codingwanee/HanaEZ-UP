package com.ez.hana.vo;

public class CertFileVO {

	String saveName;
	String originName;
	String certId;

	public String getSaveName() {
		return saveName;
	}

	public void setSaveName(String saveName) {
		this.saveName = saveName;
	}

	public String getOriginName() {
		return originName;
	}

	public void setOriginName(String originName) {
		this.originName = originName;
	}

	public String getCertId() {
		return certId;
	}

	public void setCertId(String certId) {
		this.certId = certId;
	}

	@Override
	public String toString() {
		return "CertFileVO [saveName=" + saveName + ", originName=" + originName + ", certId=" + certId + "]";
	}

}
