package com.ez.hana;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.ez.hana.dao.CodeDAO;
import com.ez.hana.vo.CountryVO;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath:config/spring/*.xml"})
public class CodeTest {
	
	@Autowired
	SqlSessionTemplate sqlSession;
	
	@Autowired
	CodeDAO codeDAO;
	
	@Test
	public void 국가코드테스트() {
		String country = "KR";
		CountryVO vo = codeDAO.getCountry(country);
		System.out.println("country" + country);
		System.out.println(vo.getNameEn());
	}

}
