package com.ez.hana.util;

import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.vo.MemberVO;

@RequestMapping("/otpGenerator")
@Controller
public class OtpGenerator {
 
	@GetMapping
    public ModelAndView otpGenerator(HttpServletRequest request, HttpServletResponse response, HttpSession session) throws ServletException, IOException {         

		// Allocating the buffer
//      byte[] buffer = new byte[secretSize + numOfScratchCodes * scratchCodeSize];
        byte[] buffer = new byte[5 + 5 * 5];
         
        // Filling the buffer with random numbers.
        // Notice: you want to reuse the same random generator
        // while generating larger random number sequences.
        new Random().nextBytes(buffer);
 
        // Getting the key and converting it to Base32
        Base32 codec = new Base32();
//      byte[] secretKey = Arrays.copyOf(buffer, secretSize);
        byte[] secretKey = Arrays.copyOf(buffer, 10);
        byte[] bEncodedKey = codec.encode(secretKey);
         
        // 생성된 Key!
        String encodedKey = new String(bEncodedKey);
         
        System.out.println("encodedKey : " + encodedKey);
        
        
        MemberVO loginVO = (MemberVO) session.getAttribute("loginVO");
        String userName = loginVO.getId();
        String hostName = "HanaEZ UP";
        
//      String url = getQRBarcodeURL(userName, hostName, secretKeyStr);
        String url = getQRBarcodeURL(userName, hostName, encodedKey); // 생성된 바코드 주소!
        System.out.println("URL : " + url);
        
        ModelAndView mav = new ModelAndView("sample/sample");
        
        mav.addObject("encodedKey", encodedKey);
        mav.addObject("url", url);
        
        return mav;
         
    }
     
    private static String getQRBarcodeURL(String user, String host, String secret) {
        String format = "http://chart.apis.google.com/chart?cht=qr&amp;chs=300x300&amp;chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s&amp;chld=H|0";
         
        return String.format(format, user, host, secret);
    }
     
}