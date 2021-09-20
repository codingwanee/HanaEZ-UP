package com.ez.hana.admin.service;

import java.util.List;

import com.ez.hana.vo.TranslatorVO;

public interface AdTranslatorService {
	
	/**
	 * 통역사 신청 목록 조회
	 * @return translatorList
	 */
	public List<TranslatorVO> getTranslatorList();
	
	/**
	 * 상세내용 조회
	 * @return translatorVO
	 */
	public TranslatorVO getTranslatorDetail(int tid);
	
	/**
	 * 활동중인 통역사 조회
	 */
	public List<TranslatorVO> getActiveTranslatorList(); 
	
	
}
