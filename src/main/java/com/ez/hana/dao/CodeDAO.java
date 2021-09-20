package com.ez.hana.dao;

import com.ez.hana.vo.CountryVO;

public interface CodeDAO {
	
	/**
	 * 국가명 또는 국가 코드를 받아 해당국가에 대한 표기명 객체반환
	 * @param country 국가코드 또는 국가명
	 * @return countryVO 넘겨받은 표기명 객체
	 */
	public CountryVO getCountry(String country);
}
