package com.ez.hana.dao;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.ez.hana.vo.CountryVO;

@Repository
public class CodeDAOImpl implements CodeDAO {

	@Autowired
	SqlSessionTemplate sqlSession;

	
	/**
	 * 국가명 또는 국가 코드를 받아 해당국가에 대한 표기명 객체반환
	 * @param country 국가코드 또는 국가명
	 * @return countryVO 넘겨받은 표기명 객체
	 */
	@Override
	public CountryVO getCountry(String country) {
		CountryVO countryVO = sqlSession.selectOne("codeMapper.selectOneCountry", country);
		return countryVO;
	}
	
}
