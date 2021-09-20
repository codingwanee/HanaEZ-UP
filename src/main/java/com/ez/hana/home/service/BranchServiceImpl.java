package com.ez.hana.home.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ez.hana.dao.BranchDAO;
import com.ez.hana.dao.ReservationDAO;
import com.ez.hana.vo.BranchVO;
import com.ez.hana.vo.ReservationVO;

@Service
public class BranchServiceImpl implements BranchService {

	@Autowired
	BranchDAO branchDAO;
	
	@Autowired
	ReservationDAO reservDAO;
	
	@Override
	public void registerBranch(BranchVO branchVO) {
		branchDAO.insert(branchVO);		
	}
	
	@Override
	public List<BranchVO> searchBranches(String keyword) {
		List<BranchVO> branchList = branchDAO.selectByKeyword(keyword);
		return branchList;
	}
	
	@Override
	public BranchVO getBranchInfo(String bid) {
		BranchVO branchVO = branchDAO.selectOne(bid);
		return branchVO;
	}
	
	/**
	 * 고객의 예약등록
	 * @param reservVO
	 */
	@Override
	public void reservate(ReservationVO reservVO) {
		reservDAO.insertReservation(reservVO);
	}

}
