package com.ez.hana.home.controller;

import java.io.IOException;
import java.io.PrintWriter;

import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.home.service.MailSendService;
import com.ez.hana.util.ValidationUtils;

@RequestMapping("/authmail")
@Controller
public class MailController {
	
	@Autowired
    JavaMailSender mailSender;
	@Autowired
	MailSendService mailSendService;
	@Autowired
	ValidationUtils validationUtils;
	
	@GetMapping
	public String authmail() {
		return "home/certify/authmail";
	}
	

	@GetMapping("/input")
	public String authinput() {
		return "home/certify/authinput";
	}
	
	 @ResponseBody
	 @GetMapping("/sending/{mailTo}")
     public String mailSending(String mail, HttpServletResponse response,
    		 				@PathVariable("mailTo") String mailTo) throws IOException {
// 	 public void mailSending(HttpServletRequest request, String mail, HttpServletResponse response

		 System.out.println("mailSending controller entered . . .");
		 
		 System.out.println("mailTo : " + mailTo);
         // Random r = new Random();
         // int authCode = r.nextInt(4589362) + 49311; //이메일로 받는 인증코드 부분 (난수)
         
         String authCode = Integer.toString(validationUtils.getAuthCode());
         
         String mailFrom = "helpingcrewcenter@gmail.com";
//       String mailTo = request.getParameter("mail"); // 받는 사람 이메일
         String title = "비대면 인증신청 완료안내 메일입니다."; // 제목
         String content = 
         System.getProperty("line.separator")+         
         System.getProperty("line.separator")+         
         "안녕하세요 손님. 저희 홈페이지를 찾아주셔서 감사합니다"         
         +System.getProperty("line.separator")+         
         System.getProperty("line.separator")+ 
         " 인증번호는 " + authCode + " 입니다. "   +
         System.getProperty("line.separator")+         
         System.getProperty("line.separator")+
         "받으신 인증번호를 홈페이지에 입력해 주시면 다음으로 넘어갑니다." +         
         System.getProperty("line.separator")+         
         System.getProperty("line.separator")+
         "Hello our customer. Thank you for using HanaEZ-UP service" +
         System.getProperty("line.separator")+         
         System.getProperty("line.separator")+         
         "Your validation code is " + authCode +         
         System.getProperty("line.separator")+         
         System.getProperty("line.separator")+         
         "Please input your vaildation code at webpage and keep certifying process." +
         System.getProperty("line.separator")+         
         System.getProperty("line.separator")+         
         "Thank you."     
         ; // 내용
         
         
         try {
             MimeMessage message = mailSender.createMimeMessage();
             MimeMessageHelper messageHelper = new MimeMessageHelper(message,
                     true, "UTF-8");

             messageHelper.setFrom(mailFrom); // 보내는사람 생략하면 정상작동을 안함
             messageHelper.setTo(mailTo); // 받는사람 이메일
             messageHelper.setSubject(title); // 메일제목은 생략이 가능하다
             messageHelper.setText(content); // 메일 내용
             
             mailSender.send(message);
         } catch (Exception e) {
             System.out.println(e);
         }
         
         // ModelAndView mav = new ModelAndView("home/certify/authinput");
         // mav.addObject("authCode", authCode);         
         // System.out.println("mav : "+mav);

         response.setContentType("text/html; charset=UTF-8");
         PrintWriter out_email = response.getWriter();
         out_email.println("<script>alert('이메일이 발송되었습니다. 인증번호를 입력해주세요.');</script>");
         out_email.flush();         
         
         System.out.println("controller ended . . .. authCode: " + authCode);
         
         return authCode;
     }

 //이메일로 받은 인증번호를 입력하고 전송 버튼을 누르면 맵핑되는 메소드.
 //내가 입력한 인증번호와 메일로 입력한 인증번호가 맞는지 확인해서 맞으면 회원가입 페이지로 넘어가고,
 //틀리면 다시 원래 페이지로 돌아오는 메소드
 @PostMapping("/validation/{authCode}")
 public ModelAndView mailValidation(String inputCode, @PathVariable("authCode") String authCode, HttpServletResponse response) throws IOException {
     
     System.out.println("마지막 : authCode : "+authCode);
     
     //페이지이동과 자료를 동시에 하기위해 ModelAndView를 사용해서 이동할 페이지와 자료를 담음      
     ModelAndView mav = null;
     
     // 일치할 경우
     if (inputCode.equals(authCode)) {    	 
    	 
    	 // 홈으로 이동
    	 mav = new ModelAndView("index");
         
         //만약 인증번호가 같다면 이메일을 회원가입 페이지로 같이 넘겨서 이메일을 다시 입력할 필요
         response.setContentType("text/html; charset=UTF-8");
         PrintWriter out_equals = response.getWriter();
         out_equals.println("<script>alert('인증번호가 일치하였습니다. 과정을 계속합니다..');</script>");
         out_equals.flush();
 
         return mav;         
         
     // 일치하지 않을 경우
     } else {
       
    	 mav = new ModelAndView("/sample");
        
         response.setContentType("text/html; charset=UTF-8");
         PrintWriter out_equals = response.getWriter();
         out_equals.println("<script>alert('인증번호가 일치하지않습니다. 인증번호를 다시 입력해주세요.'); history.go(-1);</script>");
         out_equals.flush();         
 
         return mav;
         
     }
     
 }

	

}
