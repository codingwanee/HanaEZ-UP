package com.ez.hana.home.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.home.service.BranchService;
import com.ez.hana.vo.BranchVO;
import com.ez.hana.vo.MemberVO;
import com.ez.hana.vo.ReservationVO;

@RequestMapping("/branch")
@Controller
public class BranchController {

	@Autowired
	BranchService branchService;
	
	@GetMapping
	public String branchPage() {
		return "home/branch/branch";
	}

	@ResponseBody
	@GetMapping("/search/{keyword}")
	public List<BranchVO> branchSearch(@PathVariable("keyword") String keyword) {
		List<BranchVO> branchList = branchService.searchBranches(keyword);

		/*
		for(BranchVO brn : branchList) {
			brn.setBid("a" + brn.getBid());
		}
		*/
		
		return branchList;
	}
	
	@GetMapping("/reserv/{branch}")
	public ModelAndView reservForm(@PathVariable("branch") String branch) {
		ModelAndView mav = new ModelAndView("home/branch/reservation");
				
		BranchVO branchVO = branchService.getBranchInfo(branch);
//		BranchVO branchVO = branchService.getBranchInfo("0814474");
				
		mav.addObject("branchVO", branchVO);	
				
		return mav;
	}

	/*
	@GetMapping("/reserv/{branch}")
	public ModelAndView reservForm(@PathVariable("branch") String branch) {
		ModelAndView mav = new ModelAndView("home/branch/reservation");
		
		String bid = branch.substring(0);
		
		BranchVO branchVO = branchService.getBranchInfo(bid);
		mav.addObject("branchVO", branchVO);	
		
		return mav;
	}
	*/
	
	@PostMapping("/reserv")
	public ModelAndView reservProcess(HttpServletRequest request, ReservationVO reservVO) {
		HttpSession session = request.getSession();
		MemberVO loginVO = (MemberVO)session.getAttribute("loginVO");
		String member = loginVO.getId();
		
		reservVO.setMember(member);		
		branchService.reservate(reservVO);
				
		ModelAndView mav = new ModelAndView("home/branch/completed");
		mav.addObject("reservVO", reservVO);
		
		return mav;
	}

}
