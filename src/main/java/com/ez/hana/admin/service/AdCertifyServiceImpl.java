package com.ez.hana.admin.service;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ez.hana.dao.CertifyDAO;
import com.ez.hana.dao.MemberDAO;
import com.ez.hana.vo.CertHistoryVO;
import com.ez.hana.vo.MemberVO;

@Service
public class AdCertifyServiceImpl implements AdCertifyService {

	@Autowired
	CertifyDAO certifyDAO;
	
	@Autowired
	MemberDAO memberDAO;
	
	
	// 신청기록 전체조회 > 신청목록
	@Override
	public List<CertHistoryVO> getCertList() {
		List<CertHistoryVO> certList = certifyDAO.selectAllHistory();
		return certList;
	}
	
	// 신청기록 상세조회
	@Override
	public CertHistoryVO getCertHistory(String certId) throws IOException {
		CertHistoryVO certHistoryVO = certifyDAO.selectOneHistory(certId);
		return certHistoryVO;
	}

	// 지난기록 조회
	@Override
	public List<CertHistoryVO> getPastHistory(String applicantId) {
		List<CertHistoryVO> certHistoryVO = certifyDAO.selectAllByApplicant(applicantId);
		return certHistoryVO;
	}
	
	@Override
	public MemberVO getApplicantInfo(String applicantId) {
		MemberVO memberVO = new MemberVO();
		memberVO.setId(applicantId);
		MemberVO applicantVO = memberDAO.selectOne(memberVO);
		return applicantVO;
	}
	
	// 미처리 건수 조회
	@Override
	public int getUntreatedCount() {
		int count = certifyDAO.selectCount();
		return count;
	}

	// 승인 처리
	@Override
	public void approveCertification(String certId) {
		CertHistoryVO certHistoryVO = new CertHistoryVO();
		certHistoryVO.setCertId(certId);
		certHistoryVO.setStatus("1");
		certHistoryVO.setReason("정상승인");
		
		MemberVO memberVO = new MemberVO();
		memberVO.setId(certHistoryVO.getApplicantId());
		
		certifyDAO.updateCertStatus(certHistoryVO);
		memberDAO.updateCertStatus(memberVO);
	}
	
	// 승인 거절
	public void denyCertification(CertHistoryVO certHistoryVO) {	
		certHistoryVO.setStatus("2");		
		certifyDAO.updateCertStatus(certHistoryVO);
	}
	
}
