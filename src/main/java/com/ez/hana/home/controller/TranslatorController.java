package com.ez.hana.home.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.dao.BranchDAO;
import com.ez.hana.home.service.TranslatorService;
import com.ez.hana.vo.BranchVO;
import com.ez.hana.vo.MemberVO;
import com.ez.hana.vo.TranslatorVO;

@RequestMapping("/translator")
@Controller
public class TranslatorController {

	@Autowired
	TranslatorService translatorService;
	
	@Autowired
	BranchDAO branchDAO;
	
	// 인트로 페이지 반환
	@GetMapping
	public String translatorIntroduce() {
		return "home/translator/introduce";
	}
	
	// 등록 페이지 반환
	@GetMapping("/register")
	public ModelAndView registerPage() {
		ModelAndView mav = new ModelAndView("home/translator/register");
		List<BranchVO> branchList = branchDAO.selectAll();
		mav.addObject("branchList", branchList);
		return mav;
	}
	
	// 통역사 등록 프로세스
	@PostMapping("/register")
	public String registerProcess(HttpServletRequest request, TranslatorVO translatorVO) {
		HttpSession session = request.getSession();
		MemberVO loginVO = (MemberVO) session.getAttribute("loginVO");		
		translatorVO.setApplicantId(loginVO.getId());
		System.out.println("controller : " + translatorVO.toString());
		translatorService.registerTranslator(translatorVO);
		return "redirect:/";
	}
	
	
	
}
