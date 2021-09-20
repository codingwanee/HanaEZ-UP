package com.ez.hana.dao;

import java.util.List;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.ez.hana.vo.ReservationVO;

@Repository
public class ReservationDAOImpl implements ReservationDAO {
	
	@Autowired
	SqlSessionTemplate sqlSession;

	/**
	 * 최근 3개월 이내 모든 예약기록 반환
	 * @param today 오늘날짜
	 */
	@Override
	public List<ReservationVO> selectAll(String today) {
		List<ReservationVO> reservationVO = sqlSession.selectList("reservationMapper.selectAll", today);
		return reservationVO;
	}

	/**
	 * 특정 지점의 당일 미처리 예약목록을 반환
	 * @param reservationVO  예약내역
	 */
	@Override
	public List<ReservationVO> selectByBranch(ReservationVO reservationVO) {
		List<ReservationVO> reservVO = sqlSession.selectList("reservationMapper.selectByBranch", reservationVO);
		return reservVO;
	}
	
	/**
	 * 고객의 예약등록
	 * @param reservVO
	 */
	@Override
	public void insertReservation(ReservationVO reservVO) {
		sqlSession.insert("reservationMapper.insertOne", reservVO);		
	}

}
