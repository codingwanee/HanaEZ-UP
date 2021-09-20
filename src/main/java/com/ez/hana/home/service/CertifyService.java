package com.ez.hana.home.service;

import com.ez.hana.vo.CertFileVO;
import com.ez.hana.vo.CertHistoryVO;

public interface CertifyService {
	
	/**
	 * 파일정보 저장
	 * @param certFileVO 파일정보 객체
	 */
	public void saveFileInfo(CertFileVO certFileVO);

	/**
	 * 시퀀스 반환
	 * @return seq
	 */
	public int getSeq();
	
	/**
	 * 신청내역 생성(파일 업로드 포함)
	 * @param certHistoryVO 신청내역정보 객체
	 */
	public void saveCertHistory(CertHistoryVO certHistoryVO);
	
	
	
}