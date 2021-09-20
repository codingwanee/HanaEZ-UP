package com.ez.hana.home.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@RequestMapping("/account")
@Controller
public class AccountController {
	
	@GetMapping("/open")
	public String openPage() {
		return "home/account/open";
	}
	
	@GetMapping("/easyone")
	public String easyone() {
		return "home/account/easyone";
	}

}
