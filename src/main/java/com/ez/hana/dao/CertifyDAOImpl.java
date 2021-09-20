package com.ez.hana.dao;

import java.util.List;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.ez.hana.vo.CertFileVO;
import com.ez.hana.vo.CertHistoryVO;

@Repository
public class CertifyDAOImpl implements CertifyDAO {
	
	@Autowired
	SqlSessionTemplate sqlSession;
	
	/**
	 * 파일정보 DB에 저장
	 * @param CertFileVO 파일정보를 담은 객체
	 */
	@Override
	public void insertFile(CertFileVO certFileVO) {
		System.out.println(certFileVO.toString());
		sqlSession.insert("certifyMapper.insertFile", certFileVO);		
	}
	
	/**
	 * 비대면 인증신청 번호에 쓸 시퀀스 반환
	 * @return seq 비대면 인증신청번호 시퀀스
	 */
	@Override
	public int selectSeq() {
		int seq = sqlSession.selectOne("certifyMapper.selectSeq");
		return seq;
	}
	
	/**
	 * 비대면 인증신청 정보삽입
	 * @param certHistoryVO
	 */
	@Override
	public void insertHistory(CertHistoryVO certHistoryVO) {
		System.out.println("certHistoryVO: " + certHistoryVO.toString());
		sqlSession.insert("certifyMapper.insertHistory", certHistoryVO);		
	}
	
	/**
	 * 신청기록 전체조회
	 * @return certList
	 */
	@Override
	public List<CertHistoryVO> selectAllHistory() {
		List<CertHistoryVO> certList = sqlSession.selectList("certifyMapper.selectAllHistory");
		return certList;
	}
	
	/**
	 * 신청기록 상세조회
	 * @return certHistoryVO
	 */
	@Override
	public CertHistoryVO selectOneHistory(String certId) {
		CertHistoryVO certHistoryVO = sqlSession.selectOne("certifyMapper.selectOneHistory", certId);
		return certHistoryVO;
	}
	
	/**
	 * 신청자의 지난기록 조회
	 */
	@Override
	public List<CertHistoryVO> selectAllByApplicant(String applicantId) {
		List<CertHistoryVO> certHistoryList = sqlSession.selectList("certifyMapper.selectAllByApplicant", applicantId);
		return certHistoryList;
	}
	
	// 미처리 건수 조회
	@Override
	public int selectCount() {
		int count = sqlSession.selectOne("certifyMapper.selectCount");
		return count;
	}
	
	// 처리상태 변경
	@Override
	public void updateCertStatus(CertHistoryVO certHistoryVO) {
		sqlSession.update("certifyMapper.updateStatus", certHistoryVO);		
	}

}
