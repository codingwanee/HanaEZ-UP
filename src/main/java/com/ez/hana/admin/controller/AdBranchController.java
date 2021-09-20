package com.ez.hana.admin.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.admin.service.AdBranchService;
import com.ez.hana.vo.BranchVO;

@RequestMapping("/admin/branch")
@Controller
public class AdBranchController {

	@Autowired
	private AdBranchService adBranchService;
	
	@GetMapping("/list")
	public ModelAndView branchList() {
		List<BranchVO> branchList = adBranchService.showAllBranches();
		ModelAndView mav = new ModelAndView("admin/branch/branchList");
		mav.addObject("branchList", branchList);

		return mav;
	}
	
	@GetMapping("/register")
	public String registerForm() {
		return "admin/branch/register";
	}
	
	@PostMapping("/register")
	public String register(BranchVO branchVO) {		
		// System.out.println(branchVO.toString());
		// System.out.println("register controller entered . . . ");
		adBranchService.registerBranch(branchVO);	
		return "redirect:/admin/branch/list";
	}
	
	
	
}
