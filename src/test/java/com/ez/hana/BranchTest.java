package com.ez.hana;

import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.ez.hana.vo.BranchVO;
import com.ez.hana.vo.ReservationVO;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {"classpath:config/spring/*.xml"})
public class BranchTest {
	
	
	@Autowired
	private SqlSessionTemplate sqlSession;
	
	@Ignore
	@Test
	public void 지점전체목록테스트() {
		List<BranchVO> branchList = sqlSession.selectList("admin.dao.BranchDAO.selectAll");
		assertNotNull(branchList);
	}
	
	@Ignore
	@Test
	public void 지점삽입테스트() {
		BranchVO branchVO = new BranchVO();
		
		branchVO.setBid("BRF004");
		branchVO.setNameKo("대림역");
		branchVO.setAddrKoNew("서울특별시 구로구 도림로 81");
		branchVO.setTel("02)863-5140");
		branchVO.setLoc("37.408940, 126.694327");	
		
		sqlSession.insert("admin.dao.AdBranchDAO.insert", branchVO);
	}
	
	@Test
	public void 지점검색테스트() {
		String keyword = "김포";
		List<BranchVO> branchList = sqlSession.selectList("branchMapper.selectSome", keyword);
		
		assertNotNull(branchList);
	}
	
	@Ignore
	@Test
	public void 예약등록테스트() {
		
		ReservationVO reservVO = new ReservationVO();
		
		reservVO.setBranch("BRF003");
		reservVO.setMember("user");
		
		sqlSession.insert("reservationMapper.insertOne", reservVO);
		
	}

}
