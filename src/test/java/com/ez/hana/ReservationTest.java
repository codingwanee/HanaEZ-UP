package com.ez.hana;

import java.util.Iterator;
import java.util.List;

import javax.servlet.jsp.tagext.IterationTag;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.ez.hana.vo.ReservationVO;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath:config/spring/*.xml"})
public class ReservationTest {
	
	@Autowired
	SqlSessionTemplate sqlSession;
	
	@Test
	public void 지점별조회테스트() {
		
		ReservationVO vo = new ReservationVO();
		
		vo.setResDate("20-09-04");
		vo.setBranch("BRF001");
		
		List<ReservationVO> list = sqlSession.selectList("reservationMapper.selectByBranch", vo);
		
		System.out.println("start");
		Iterator<ReservationVO> iter = list.iterator();
		System.out.println("end");
		
		
		while(iter.hasNext()) {
			System.out.println("hasNext");
		}
				
	}

}
