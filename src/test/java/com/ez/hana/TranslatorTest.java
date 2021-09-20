package com.ez.hana;

import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.ez.hana.dao.TranslatorDAO;
import com.ez.hana.vo.TranslatorVO;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath:config/spring/*.xml"})
public class TranslatorTest {
	
	
	@Autowired
	TranslatorDAO translatorDAO;
	
	@Test
	public void 목록테스트() {
		List<TranslatorVO> list = translatorDAO.selectAll();
		
		for(TranslatorVO vo : list) {
			System.out.println(vo.toString());
		}
	}

}
