package com.ez.hana.admin.service;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ez.hana.dao.ReservationDAO;
import com.ez.hana.vo.ReservationVO;

@Service
public class AdReservationServiceImpl implements AdReservationService {
	
	@Autowired
	ReservationDAO reservationDAO;

	/**
	 * 오늘자 모든내역 조회
	 */
	@Override
	public List<ReservationVO> displayAllReservOfToday() {
		SimpleDateFormat format = new SimpleDateFormat("yy-MM-dd");
		Date date = new Date();
		String today = format.format(date);
		List<ReservationVO> reservationList = reservationDAO.selectAll(today);
		
		return reservationList;
	}

	
	/**
	 *  지점에 따른 조회
	 */
	@Override
	public List<ReservationVO> displayReservByBranch(String branch) {
		
		ReservationVO reservationVO = new ReservationVO();
		
		SimpleDateFormat format = new SimpleDateFormat("yy-MM-dd");
		Date date = new Date();
		String today = format.format(date);
		
		reservationVO.setResDate(today);
		reservationVO.setBranch(branch);
		
		List<ReservationVO> reservationList = reservationDAO.selectByBranch(reservationVO);
				
		return reservationList;
	}

}
