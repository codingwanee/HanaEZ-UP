package com.ez.hana.dao;

import java.util.List;

import com.ez.hana.vo.TranslatorVO;

public interface TranslatorDAO {
	
	/**
	 * 통역사 등록
	 * @param translatorVO
	 */
	public void insertOne(TranslatorVO translatorVO);

	
	/**
	 * 통역사 전체 조회
	 * @return translatorList
	 */
	 public List<TranslatorVO> selectAll();
	 
	 /**
	  * 통역사 상세 조회
	  * @return translatorVO
	  */
	 public TranslatorVO selectOne(int tid);
	 
	 /**
	  * 활동중인 통역사 조회
	  * @return translatorList
	  */
	 public List<TranslatorVO> selectByStatus();
}
