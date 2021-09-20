package com.ez.hana.admin.service;

import java.util.List;

import com.ez.hana.vo.ReservationVO;

public interface AdReservationService {
	
	/**
	 * 당일 모든지점의 예약목록을 조회
	 */
	public List<ReservationVO> displayAllReservOfToday();
	
	
	/**
	 * 해당지점의 당일 예약목록을 모두 조회
	 */
	public List<ReservationVO> displayReservByBranch(String branch);

}
