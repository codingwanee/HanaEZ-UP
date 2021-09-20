package com.ez.hana.admin.controller;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.admin.service.AdEmployeeService;
import com.ez.hana.vo.EmployeeVO;
import com.ez.hana.vo.MemberVO;

@SessionAttributes({"employeeVO"})
@RequestMapping("/admin")
@Controller
public class AdGeneralController {
	
	@Autowired
	AdEmployeeService employeeService;

	@GetMapping
	public String adminMainPage(HttpSession session) {
		
		EmployeeVO employeeVO = (EmployeeVO) session.getAttribute("employeeVO");
		
		if(employeeVO == null) {			
			return "admin/login";
		}
		
		return "admin/main";
	}	
	
	@GetMapping("/login")
	public String adminLogin() {
		return "admin/login";
	}
	
	@PostMapping("/login")
	public ModelAndView empLogin(EmployeeVO employeeVO, HttpSession session) {
		EmployeeVO empVO = employeeService.login(employeeVO);
		ModelAndView mav = new ModelAndView();
		
		// 로그인 실패
		if(empVO == null) {
			mav.setViewName("redirect:/admin/login");
		
		// 로그인 성공
		} else {			
			mav.setViewName("redirect:/admin");
			mav.addObject("employeeVO", empVO);
		}
		
		return mav;
	}
	
	
	@GetMapping("/sample")
	public String sample() {
		return "admin/sample";
	}

}
