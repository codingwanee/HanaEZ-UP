package com.ez.hana.util;

import org.springframework.stereotype.Service;

//Install the Java helper library from twilio.com/docs/libraries/java
import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

// @Service
public class SmsSender {
// Find your Account Sid and Auth Token at twilio.com/console
  public static final String ACCOUNT_SID = "<spring:eval expression=\"@property['twilioSID']\"></spring:eval>";
  public static final String AUTH_TOKEN = "<spring:eval expression=\"@property['twilioToken']\"></spring:eval>";
  
// public static final String fromPhoneN = "+13236414260";
public static final String fromPhoneN = "+8216001522"; // 하나은행 안내문자번호

  private Message message;
  
  //생성자
  public SmsSender() {
     Twilio.init(ACCOUNT_SID, AUTH_TOKEN);
  }  
  
  //문자 알림 메소드
  public void send(String toPhoneNo, String msg) {
     message = Message.creator(new PhoneNumber("+82" + toPhoneNo.substring(1)), // to
              new PhoneNumber(fromPhoneN), // from
              msg).create();
      System.out.println(message.getSid());
      
  }


}