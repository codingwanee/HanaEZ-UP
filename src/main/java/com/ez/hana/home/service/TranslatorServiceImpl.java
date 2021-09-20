package com.ez.hana.home.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ez.hana.dao.TranslatorDAO;
import com.ez.hana.vo.TranslatorVO;

@Service
public class TranslatorServiceImpl implements TranslatorService {

	@Autowired
	TranslatorDAO translatorDAO;
	
	@Override
	public void registerTranslator(TranslatorVO translatorVO) {
		translatorDAO.insertOne(translatorVO);
	}

}
