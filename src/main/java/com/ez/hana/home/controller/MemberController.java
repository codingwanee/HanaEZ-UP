package com.ez.hana.home.controller;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.home.service.MemberService;
import com.ez.hana.vo.MemberVO;

@SessionAttributes({"loginVO"})
@Controller
public class MemberController {

	@Autowired
	MemberService memberService;
	
	// 로그인 페이지
	@GetMapping("/login")
	public String loginForm() {
		return "home/member/login";
	}
	
	// 로그인 기능
	@PostMapping("/login")
	public ModelAndView login(MemberVO memberVO, HttpSession session) {
		MemberVO loginVO = memberService.login(memberVO);
		ModelAndView mav = new ModelAndView();

		// 로그인 실패
		if(loginVO == null) {
			mav.setViewName("redirect:/login");
		
		// 로그인 성공
		} else {	
		
			// 원래 사용자가 있던 페이지로 돌려보냄
			String dest = (String)session.getAttribute("dest");
			if(dest == null) {
				mav.setViewName("redirect:/");
			} else {
				mav.setViewName("redirect:/" + dest);				
				session.removeAttribute("dest");
			}			
			
			mav.addObject("loginVO", loginVO);
		}
		
		return mav;
	}

	@RequestMapping("/logout")
	public String logout(SessionStatus status) {
		status.setComplete(); // 세션 초기화		
		return "redirect:/";
	}
	
	@GetMapping("/join")
	public String joinForm() {
		return "home/member/join";
	}

	@PostMapping("/join")
	public ModelAndView join() {
		ModelAndView mav = new ModelAndView();
		
		return mav;
	}

	// 마이페이지
	@GetMapping("/mypage")
	public ModelAndView mypage(HttpSession session) {
		
		MemberVO memberVO = memberService.mypage((MemberVO)session.getAttribute("loginVO"));
		ModelAndView mav = new ModelAndView("home/member/mypage");
		mav.addObject("memberVO", memberVO);
		return mav;
	}

	// 가짜 로그인
	@GetMapping("/fakelogin")
	public ModelAndView fakeLogin(HttpSession session) {		
		ModelAndView mav = new ModelAndView("index");	
		
		String dest =  (String)session.getAttribute("dest");
		if(dest == null) {
			mav.setViewName("redirect:/");
		} else {
			mav.setViewName("redirect:/" + dest);				
			session.removeAttribute("dest");
		}
		
		MemberVO fakeloginVO = new MemberVO();
		fakeloginVO.setId("indra");
		fakeloginVO.setType("0");
		
		mav.addObject("loginVO", fakeloginVO);
		
		return mav;
	}

	@ResponseBody
	@GetMapping("/idCheck")
	public Boolean idCheck(String id) {
		
		Boolean bool = memberService.checkIdDuplicated(id);
		
		return bool;
	}
}
