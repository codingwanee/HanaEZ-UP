package com.ez.hana.admin.service;

import java.util.List;

import com.ez.hana.vo.BranchVO;

public interface AdBranchService {

	/**
	 * 지점 전체목록 조회
	 * @return List<BranchVO>
	 */
	public List<BranchVO> showAllBranches();

	/**
	 * 새 지점 등록
	 * @param branchVO 등록한 지점정보
	 */
	public void registerBranch(BranchVO branchVO);

}
