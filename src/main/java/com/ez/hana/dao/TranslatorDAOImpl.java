package com.ez.hana.dao;

import java.util.List;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.ez.hana.vo.TranslatorVO;

@Repository
public class TranslatorDAOImpl implements TranslatorDAO {

	@Autowired
	SqlSessionTemplate sqlSession;
	
	// 통역사 등록
	@Override
	public void insertOne(TranslatorVO translatorVO) {
		System.out.println("controller : " + translatorVO.toString());
		sqlSession.insert("translatorMapper.insertOne", translatorVO);
	}
	
	// 통역사 목록 조회
	@Override
	public List<TranslatorVO> selectAll() {
		List<TranslatorVO> translatorList = sqlSession.selectList("translatorMapper.selectAll");
		return translatorList;
	}
	
	// 통역사 상세 조회
	@Override
	public TranslatorVO selectOne(int tid) {
		TranslatorVO translatorVO = sqlSession.selectOne("translatorMapper.selectOne", tid);
		return translatorVO;
	}
	
	// 활동중인 통역사 조회
	@Override
	public List<TranslatorVO> selectByStatus() {
		List<TranslatorVO> translatorList = sqlSession.selectList("translatorMapper.selectByStatus");
		return translatorList;
	}

}
