package com.ez.hana.home.service;

import org.springframework.stereotype.Service;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

@Service
public class SmsSenderServiceImpl implements SmsSenderService {
	
	
	// Find your Account Sid and Auth Token at twilio.com/console
	  public static final String ACCOUNT_SID = "AC7ceb1b07f9c9f3ee256f0d7f4a61857e";
	  public static final String AUTH_TOKEN = "983be263b29c6445adbfbf4580991cac";
	  
//	public static final String fromPhoneN = "+13236414260";
	  public static final String fromPhoneN = "+12028385672"; // twilio sample number

	  private Message message;
	  
	  //생성자
	  public SmsSenderServiceImpl() {
	     Twilio.init(ACCOUNT_SID, AUTH_TOKEN);
	  }  
	  
	  //문자 알림 메소드
	  @Override
	  public void send(String smsTo, String msg) {
	     message = Message.creator(new PhoneNumber("+82" + smsTo.substring(1)), // to
	              new PhoneNumber(fromPhoneN), // from
	              msg)
	    		 .create();	      
	  }

}
