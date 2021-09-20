package com.ez.hana;

import java.util.List;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import com.ez.hana.dao.CertifyDAO;
import com.ez.hana.vo.CertHistoryVO;

@WebAppConfiguration
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath:config/spring/*.xml"})
public class CertifyTest {

	@Autowired
	SqlSessionTemplate sqlSession;
	
	@Autowired
	CertifyDAO certifyDAO;
	
	@Ignore
	@Test
	public void 맵퍼테스트() {
		CertHistoryVO certHistoryVO = new CertHistoryVO();
		
		certHistoryVO.setCertId("test000002");
		certHistoryVO.setApplicantId("user");
		certHistoryVO.setApplicantNm("user");
		certHistoryVO.setApplicantNtnEn("korea");
		certHistoryVO.setFileName("aaaaa");
		
		certifyDAO.insertHistory(certHistoryVO);
	}

	@Ignore
	@Test
	public void 시퀀스생성테스트() {
		
	
		int a = 66;
		String b = String.format("%08d", a);
		System.out.println("print");
		System.out.println(b);
	}
	
	@Ignore
	@Test
	public void 목록조회테스트() {
		List<CertHistoryVO> certHistoryList = sqlSession.selectList("certifyMapper.selectAllHistory");
				
	}
	
	@Test
	public void 카운트테스트() {
		int count = certifyDAO.selectCount();
		System.out.println(count);
	}
	
}
