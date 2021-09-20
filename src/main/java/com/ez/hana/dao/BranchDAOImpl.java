package com.ez.hana.dao;

import java.util.List;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.ez.hana.vo.BranchVO;

@Repository
public class BranchDAOImpl implements BranchDAO {
	
	@Autowired
	SqlSessionTemplate sqlSession;
	
	/**
	 * 지점 검색하는 기능
	 */
	@Override
	public List<BranchVO> selectByKeyword(String keyword) {		
		List<BranchVO> branchList = sqlSession.selectList("branchMapper.selectSome", keyword);
		return branchList;
	}
	
	/**
	 * 지점 등록
	 */
	@Override
	public void insert(BranchVO branchVO) {
		sqlSession.insert("branchMapper.insert", branchVO);
	}
	
	/**
	 * 지점 전체목록 조회
	 */
	@Override
	public List<BranchVO> selectAll() {
		List<BranchVO> branchList = sqlSession.selectList("branchMapper.selectAll");
		return branchList;
	}
	
	/**
	 * bid로 지점정보 조회
	 */
	@Override
	public BranchVO selectOne(String bid) {
		BranchVO branchVO = sqlSession.selectOne("branchMapper.selectOne", bid);
		return branchVO;
	}
	
	
}
