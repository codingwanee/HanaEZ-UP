package com.ez.hana;

import static org.junit.Assert.assertNotNull;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.ez.hana.dao.MemberDAO;
import com.ez.hana.vo.MemberVO;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath:config/spring/*.xml"})
public class MemberTest {

	@Autowired
	private MemberDAO memberDAO;
	
	@Autowired
	private SqlSessionTemplate sqlSession;
	
	@Ignore
	@Test
	public void 로그인테스트() throws Exception {
		
		MemberVO member = new MemberVO();
		member.setId("user");
		member.setPassword("user");
		
		MemberVO loginVO = memberDAO.login(member);
		
		assertNotNull(loginVO);
	}
	
	@Test
	public void 마이페이지테스트() throws Exception {
		MemberVO loginVO = new MemberVO();
		
		loginVO.setId("user");
		
		MemberVO memberVO = sqlSession.selectOne("home.dao.MemberDAO.selectOne", loginVO);
	}
	
}
