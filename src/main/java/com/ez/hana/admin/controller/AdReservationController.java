package com.ez.hana.admin.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.admin.service.AdReservationService;
import com.ez.hana.vo.EmployeeVO;
import com.ez.hana.vo.ReservationVO;

@RequestMapping("/admin/reserv")
@Controller
public class AdReservationController {

	@Autowired
	AdReservationService reservationService;
	
	
	/**
	 * 지점별 예약내역 조회
	 * @param branch
	 */
	@GetMapping("/list")
	public ModelAndView reservTodayOfBranch(HttpServletRequest request) {
		
		HttpSession session = request.getSession();
		EmployeeVO employeeVO = (EmployeeVO) session.getAttribute("employeeVO");
		
		ModelAndView mav = new ModelAndView("admin/reserv/reservList");		
		List<ReservationVO> reservationList = reservationService.displayReservByBranch(employeeVO.getBranch());
		
		ReservationVO reservationVO = new ReservationVO();
		if(reservationList== null) {
			reservationVO.setMember("none");
			reservationVO.setService("none");
			reservationVO.setResId("none");
			reservationVO.setResTime("none");
		}
		reservationList.add(reservationVO);
		
		mav.addObject("reservationList", reservationList);
		
		return mav;
	}
	
}
