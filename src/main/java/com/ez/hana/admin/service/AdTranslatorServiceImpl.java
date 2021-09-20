package com.ez.hana.admin.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ez.hana.dao.TranslatorDAO;
import com.ez.hana.vo.TranslatorVO;

@Service
public class AdTranslatorServiceImpl implements AdTranslatorService {

	@Autowired
	TranslatorDAO translatorDAO;
	
	// 통역사 목록 조회
	@Override
	public List<TranslatorVO> getTranslatorList() {
		List<TranslatorVO> translatorList = translatorDAO.selectAll();
		return translatorList;
	}
	
	// 통역사 상세 조회
	@Override
	public TranslatorVO getTranslatorDetail(int tid) {
		TranslatorVO translatorVO = translatorDAO.selectOne(tid);		
		return translatorVO;
	}
	
	// 활동중인 통역사 조회
	@Override
	public List<TranslatorVO> getActiveTranslatorList() {
		List<TranslatorVO> translatorList = translatorDAO.selectByStatus();
		return translatorList;
	}
}
