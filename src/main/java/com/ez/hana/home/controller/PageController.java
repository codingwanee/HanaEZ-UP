package com.ez.hana.home.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {
	
	@GetMapping("/exchangeRate")
	public String exchangeRate() {
		return "home/exchange/exchangeRate";
	}
	
	@GetMapping("/cards")
	public String cardBrochure() {
		return "home/card/brochure";
	}
	
	@GetMapping("/foreignerService")
	public String foreignerService() {
		return "home/info/foreignerService";
	}

}
