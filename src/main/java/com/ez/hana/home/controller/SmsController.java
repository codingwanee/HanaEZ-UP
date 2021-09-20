package com.ez.hana.home.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.home.service.SmsSenderService;
import com.ez.hana.util.ValidationUtils;

@RequestMapping("/sms")
@Controller
public class SmsController {
	
	@Autowired
	SmsSenderService smsSenderService;
	@Autowired
	ValidationUtils validationUtils;
	
	@ResponseBody
	@GetMapping("/sending/{smsTo}")
		public String smsSending(@PathVariable("smsTo") String smsTo) {	
//		ajax가 아닌 페이지 이동 방식으로 할 때		
//		public String smsSending(HttpServletRequest request) {	
		System.out.println("SmsController entered . . .");

		String authCode = Integer.toString(validationUtils.getAuthCode());
//		String smsTo = request.getParameter("smsTo");
		String msg = "인증번호는 [" + authCode + "] 입니다.";
		
		System.out.println("authCode generated : " + authCode);
		
		smsSenderService.send(smsTo, msg);		
	
		// 뻘짓의 흔적
//		pageContext.setAttribute("authCode", authCode);
		
		System.out.println("controller ended. . .");
		
		return authCode;
	}
	
	@GetMapping("/test")
	public ModelAndView smsTest() {
		System.out.println("test controller entered . . .");
		
		ModelAndView mav = new ModelAndView("index");
		
		String toPhoneNo = "01053514241";
		String msg = "test";
		smsSenderService.send(toPhoneNo, msg);		
		
		return mav;
	}
	

}
