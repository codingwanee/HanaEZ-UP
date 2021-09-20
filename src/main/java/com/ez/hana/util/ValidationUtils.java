package com.ez.hana.util;

import java.util.Random;

import org.springframework.stereotype.Service;

@Service
public class ValidationUtils {
	
	Random r = new Random();

	
	public int getAuthCode() {		
		System.out.println("test");
		int authCode = r.nextInt(4589362) + 49311; //이메일로 받는 인증코드 부분 (난수)
		System.out.println("authCode : " + authCode);
	
		return authCode;
	}
	
	
}
