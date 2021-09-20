package com.ez.hana.vo;


public class ReservationVO {
	String resId;
	String branch;
	String member;
//	String country;
	String resDate;
	String resTime;
	String service;
	String status;
	String regDate;

	public String getResId() {
		return resId;
	}

	public void setResId(String resId) {
		this.resId = resId;
	}

	public String getBranch() {
		return branch;
	}

	public void setBranch(String branch) {
		this.branch = branch;
	}

	public String getMember() {
		return member;
	}

	public void setMember(String member) {
		this.member = member;
	}

	public String getResDate() {
		return resDate;
	}

	public void setResDate(String resDate) {
		this.resDate = resDate;
	}

	public String getResTime() {
		return resTime;
	}

	public void setResTime(String resTime) {
		this.resTime = resTime;
	}

	public String getService() {
		return service;
	}

	public void setService(String service) {
		this.service = service;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getRegDate() {
		return regDate;
	}

	public void setRegDate(String regDate) {
		this.regDate = regDate;
	}

	@Override
	public String toString() {
		return "ReservationVO [resId=" + resId + ", branch=" + branch + ", member=" + member + ", resDate=" + resDate
				+ ", resTime=" + resTime + ", service=" + service + ", status=" + status + ", regDate=" + regDate + "]";
	}

}
