package com.ez.hana.admin.controller;

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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.admin.service.AdTranslatorService;
import com.ez.hana.vo.TranslatorVO;

@RequestMapping("/admin/translator")
@Controller
public class AdTranslatorController {
	
	@Autowired
	AdTranslatorService adTranslatorService;
	
	// 등록된 통역사 목록 반환
	@GetMapping
	public ModelAndView translatorList() {
		ModelAndView mav = new ModelAndView("/admin/translator/list");
		List<TranslatorVO> translatorList = adTranslatorService.getTranslatorList();
		mav.addObject("translatorList", translatorList);
		/*
		for(TranslatorVO vo : translatorList) {
			System.out.println(vo.toString());
		}
		*/
		return mav;
	}
	
	// 등록된 통역사 목록 반환
	@GetMapping("/active")
	public ModelAndView translatorActiveList() {
		ModelAndView mav = new ModelAndView("/admin/translator/activeList");
		List<TranslatorVO> translatorList = adTranslatorService.getActiveTranslatorList();
		mav.addObject("translatorList", translatorList);
		/*
		for(TranslatorVO vo : translatorList) {
			System.out.println(vo.toString());
		}
		 */
		return mav;
	}
	
	
	@RequestMapping("/excel")
	public void excelDown(HttpServletResponse response) throws Exception {

		// 게시판 목록조회
		List<TranslatorVO> list = adTranslatorService.getTranslatorList();

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
		cell.setCellValue("언어");
		cell = row.createCell(idx++);
		cell.setCellStyle(headStyle);
		cell.setCellValue("레벨");
		cell = row.createCell(idx++);
		cell.setCellStyle(headStyle);
		cell.setCellValue("자기소개");
		cell = row.createCell(idx++);
		cell.setCellStyle(headStyle);
		cell.setCellValue("신청일");

		// 데이터 부분 생성
		for (TranslatorVO vo : list) {
			
			int loc = 0;
			row = sheet.createRow(rowNo++);
			
			cell = row.createCell(loc++);
			cell.setCellStyle(bodyStyle);
			cell.setCellValue(vo.getTid());
			cell = row.createCell(loc++);
			cell.setCellStyle(bodyStyle);
			cell.setCellValue(vo.getApplicantId());
			cell = row.createCell(loc++);
			cell.setCellStyle(bodyStyle);
			cell.setCellValue(vo.getFirstName() + " " + vo.getLastName());
			cell = row.createCell(loc++);
			cell.setCellStyle(bodyStyle);
			cell.setCellValue(vo.getLang());
			cell = row.createCell(loc++);
			cell.setCellStyle(bodyStyle);
			cell.setCellValue(vo.getLangLv());
			cell = row.createCell(loc++);
			cell.setCellStyle(bodyStyle);
			cell.setCellValue(vo.getMessage());
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

	
	
	
}
