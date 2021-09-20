package com.ez.hana.home.controller;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import com.ez.hana.util.DetectText;

@Controller
public class SampleController {
	
//	@GetMapping("/sample")
	public String sample() throws IOException {
		
		String filePath = "D:/fileStorage/regcard.jpg";
		
		DetectText dt = new DetectText();
		dt.detectText(filePath);
		
		return "sample/sample";
	}
	
}
