package com.ez.hana.admin.controller;

import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.hssf.util.HSSFColor.HSSFColorPredefined;
import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.FillPatternType;
import org.apache.poi.ss.usermodel.HorizontalAlignment;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.admin.service.AdCertifyService;
import com.ez.hana.util.DetectText;
import com.ez.hana.vo.CertHistoryVO;
import com.ez.hana.vo.MemberVO;

@RequestMapping("/admin/certify")
@Controller
public class AdCertifyController {

	@Autowired
	AdCertifyService adCertifyService;
	
//	@Autowired
//	private CloudVisionTemplate cloudVisionTemplate;

	@GetMapping("/list")
	public ModelAndView certifyList() {
		ModelAndView mav = new ModelAndView("admin/certify/certList");
		List<CertHistoryVO> certList = adCertifyService.getCertList();
		mav.addObject("certList", certList);

		return mav;
	}

	
	// 신청내역 상세조회
	@GetMapping("/detail/{certId}")
	public ModelAndView certifyDetail(@PathVariable("certId") String certId) throws IOException {
		ModelAndView mav = new ModelAndView("admin/certify/certDetail");
		CertHistoryVO certHistoryVO = adCertifyService.getCertHistory(certId);
		List<CertHistoryVO> certHistoryList = adCertifyService.getPastHistory(certHistoryVO.getApplicantId());
		MemberVO applicantVO = adCertifyService.getApplicantInfo(certHistoryVO.getApplicantId());
		mav.addObject("certHistoryList", certHistoryList);
		mav.addObject("certHistoryVO", certHistoryVO);
		mav.addObject("applicantVO", applicantVO);
		
		// 텍스트 추출하여 반환
		String detectedStr;
		/*
		if(certHistoryVO.getFileName() == null) {
			detectedStr = DetectText.detectText();			
		} else {
			String path = "path" + certHistoryVO.getFileName();
			detectedStr = DetectText.detectText(path);
		}
		*/
		
		detectedStr = DetectText.detectText();			
		mav.addObject("detectedStr", detectedStr);

		return mav;
	}

	@ResponseBody
	@GetMapping("/count")
	public int untreatedCount() {
		int count = adCertifyService.getUntreatedCount();
		return count;
	}

	@RequestMapping("/excel")
	public void excelDown(HttpServletResponse response) throws Exception {

		// 게시판 목록조회
		List<CertHistoryVO> list = adCertifyService.getCertList();

		// 워크북 생성
		Workbook wb = new HSSFWorkbook();
		Sheet sheet = wb.createSheet("비대면 인증신청 목록");
		Row row = null;
		Cell cell = null;
		int rowNo = 0;

		// 테이블 헤더용 스타일
		CellStyle headStyle = wb.createCellStyle();

		// 제목 경계선
		headStyle.setBorderTop(BorderStyle.THIN);
		headStyle.setBorderBottom(BorderStyle.THIN);
		headStyle.setBorderLeft(BorderStyle.THIN);
		headStyle.setBorderRight(BorderStyle.THIN);

		// 제목 스타일
		headStyle.setFillForegroundColor(HSSFColorPredefined.LIGHT_GREEN.getIndex()); // 배경 연그린색
		headStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND); // 배경 채우기
		headStyle.setAlignment(HorizontalAlignment.CENTER); // 데이터 가운데 정렬

		// 데이터용 경계 스타일 테두리만 지정
		CellStyle bodyStyle = wb.createCellStyle();
		bodyStyle.setBorderTop(BorderStyle.THIN);
		bodyStyle.setBorderBottom(BorderStyle.THIN);
		bodyStyle.setBorderLeft(BorderStyle.THIN);
		bodyStyle.setBorderRight(BorderStyle.THIN);

		// 헤더 생성
		int idx = 0;
		row = sheet.createRow(rowNo++);
		cell = row.createCell(idx++);
		cell.setCellStyle(headStyle);
		cell.setCellValue("신청번호");
		cell = row.createCell(idx++);
		cell.setCellStyle(headStyle);
		cell.setCellValue("ID");
		cell = row.createCell(idx++);
		cell.setCellStyle(headStyle);
		cell.setCellValue("이름");
		cell = row.createCell(idx++);
		cell.setCellStyle(headStyle);
		cell.setCellValue("국적");
		cell = row.createCell(idx++);
		cell.setCellStyle(headStyle);
		cell.setCellValue("신청일");

		// 데이터 부분 생성
		for (CertHistoryVO vo : list) {			
			int loc = 0;
			row = sheet.createRow(rowNo++);
			
			cell = row.createCell(loc++);
			cell.setCellStyle(bodyStyle);
			cell.setCellValue(vo.getCertId());
			cell = row.createCell(loc++);
			cell.setCellStyle(bodyStyle);
			cell.setCellValue(vo.getApplicantId());
			cell = row.createCell(loc++);
			cell.setCellStyle(bodyStyle);
			cell.setCellValue(vo.getApplicantNm());
			cell = row.createCell(loc++);
			cell.setCellStyle(bodyStyle);
			cell.setCellValue(vo.getApplicantNtnKo());
			cell = row.createCell(loc++);
			cell.setCellStyle(bodyStyle);
			cell.setCellValue(vo.getRegDate());
		}

		// 컨텐츠 타입과 파일명 지정
		response.setContentType("ms-vnd/excel");
		response.setHeader("Content-Disposition", "attachment;filename=HanaEZ-certification.xls");

		// 엑셀 출력
		wb.write(response.getOutputStream());
		wb.close();

	}
	
	// 승인
	@GetMapping("/approval")
	public String approveCertification(@PathVariable("certId") String certId) {
		adCertifyService.approveCertification(certId);		
		return "admin/certify/certList";
	}
	
	// 거부
	@PostMapping("/denial")
	public String denyCertification(CertHistoryVO certHistoryVO) {
		adCertifyService.denyCertification(certHistoryVO);	
		return "admin/certify/certList";
	}
	

}
