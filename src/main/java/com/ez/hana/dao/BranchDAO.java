package com.ez.hana.dao;

import java.util.List;

import com.ez.hana.vo.BranchVO;

public interface BranchDAO {
	
	/**
	 * 지점 전체조회
	 */
	public List<BranchVO> selectAll();
	
	/**
	 * 키워드로 지점 조회
	 * @param keyword 검색키워드
	 */
	public List<BranchVO> selectByKeyword(String keyword);
	
	/**
	 * 지점코드로 지점조회
	 * @param bid 지점코드
	 * @return branchVO 지점 정보
	 */
	public BranchVO selectOne(String bid);

	/**
	 * 지점 등록
	 * @param branchVO 지점 정보
	 */
	public void insert(BranchVO branchVO);
	
}
