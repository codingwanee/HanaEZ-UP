package com.ez.hana.dao;

import java.util.List;

import com.ez.hana.vo.ReservationVO;

public interface ReservationDAO {
	
	/**
	 * 최근 3개월 이내 모든 예약기록을 반환(로그)
	 * @param branchVO
	 */
	public List<ReservationVO> selectAll(String today);
	
	/**
	 * 로그인 한 직원이 소속된 지점의 당일예약 리스트를 반환
	 * @param branchVO
	 */
	public List<ReservationVO> selectByBranch(ReservationVO reservationVO);
	
	/**
	 * 고객의 예약등록
	 * @param reservVO
	 */
	public void insertReservation(ReservationVO reservVO);

}
