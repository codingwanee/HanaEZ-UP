package com.ez.hana.admin.service;

import java.io.IOException;
import java.util.List;

import com.ez.hana.vo.CertHistoryVO;
import com.ez.hana.vo.MemberVO;

public interface AdCertifyService {
	
	/**
	 * 신청기록 전체조회
	 * @return certList
	 */
	public List<CertHistoryVO> getCertList();
	
	/**
	 * 신청기록 상세조회
	 * @return certHistoryVO
	 */
	public CertHistoryVO getCertHistory(String certId)  throws IOException;
	
	/**
	 * 신청자의 지난 신청기록 조회
	 * @return certHistoryList
	 */
	public List<CertHistoryVO> getPastHistory(String applicantId);
	
	/**
	 * HanaEZ UP에 등록된 신청자 신상정보 조회
	 */
	public MemberVO getApplicantInfo(String applicantId);
	
	/**
	 * 미처리 건수 조회
	 */
	public int getUntreatedCount();


	/**
	 * 비대면 인증 신청 승인
	 * @param certId
	 */
	public void approveCertification(String certId);

	/**
	 * 비대면 인증 신청 거부
	 * @param certHistoryVO
	 */
	public void denyCertification(CertHistoryVO certHistoryVO);
}
