package com.ez.hana.home.service;

public interface SmsSenderService {

	
	/**
	 * 문자 알림 메소드
	 * @param toPhoneNo
	 * @param msg
	 */
	public void send(String smsTo, String msg);
	
	
}
