package com.ez.hana.home.service;

import java.util.List;

import com.ez.hana.vo.BranchVO;
import com.ez.hana.vo.ReservationVO;

public interface BranchService {

	/**
	 * 새 지점 등록
	 * @param branchVO 등록한 지점정보
	 */
	public void registerBranch(BranchVO branchVO);
	
	
	/**
	 * 키워드로 지점검색
	 * @param keyword 검색키워드
	 */
	public List<BranchVO> searchBranches(String keyword);
	
	/**
	 * 지점코드로 지점조회
	 * @param bid 지점코드
	 * @return branchVO 지점 정보
	 */
	public BranchVO getBranchInfo(String bid);
	
	/**
	 * 고객의 예약 등록
	 * @param reservVO
	 */
	public void reservate(ReservationVO reservVO);
}
