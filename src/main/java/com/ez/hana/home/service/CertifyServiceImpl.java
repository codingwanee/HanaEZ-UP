package com.ez.hana.home.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ez.hana.dao.CertifyDAO;
import com.ez.hana.vo.CertFileVO;
import com.ez.hana.vo.CertHistoryVO;

@Service
public class CertifyServiceImpl implements CertifyService {

	@Autowired
	CertifyDAO certifyDAO;

	
	/**
	 * 파일정보 저장
	 * @param certFileVO
	 */
	@Override
	public void saveFileInfo(CertFileVO certFileVO) {
		certifyDAO.insertFile(certFileVO);		
	}

	/**
	 * 시퀀스 반환
	 * @return seq 신청번호에 대한 시퀀스
	 */
	@Override
	public int getSeq() {
		int seq = certifyDAO.selectSeq();
		return seq;
	};

	/**
	 * 신청내역 생성(파일 업로드 포함)
	 * @param certFileVO 파일정보 객체, certHistoryVO 신청내역정보 객체
	 */
	@Override
	public void saveCertHistory(CertHistoryVO certHistoryVO) {		
		certifyDAO.insertHistory(certHistoryVO);
	}
	
}

