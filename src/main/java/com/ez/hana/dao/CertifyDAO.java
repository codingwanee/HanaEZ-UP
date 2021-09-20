package com.ez.hana.dao;

import java.util.List;

import com.ez.hana.vo.CertFileVO;
import com.ez.hana.vo.CertHistoryVO;

public interface CertifyDAO {
	
	/**
	 * 파일정보 저장
	 * @param certFileVO
	 */
	public void insertFile(CertFileVO certFileVO);
	
	
	/**
	 * CertId 에 대한 시퀀스 반환
	 * @return seq
	 */
	public int selectSeq();
	

	/**
	 * 신청기록 저장
	 * @param certHistoryVO
	 */
	public void insertHistory(CertHistoryVO certHistoryVO);

	
	
	/**
	 * 신청기록 전체조회
	 * @return certList
	 */
	public List<CertHistoryVO> selectAllHistory();
	
	/**
	 * 신청기록 상세조회
	 * @return certHistoryVO
	 */
	public CertHistoryVO selectOneHistory(String certId);

	
	/**
	 * 신청자의 지난기록 조회
	 */
	public List<CertHistoryVO> selectAllByApplicant(String applicantId);	
	
	/**
	 * 알림을 위한 미처리 건수조회
	 */
	public int selectCount();

	/**
	 * 비대면 인증상태 승인으로 변경
	 * @param string
	 */
	public void updateCertStatus(CertHistoryVO certHistoryVO);

}
