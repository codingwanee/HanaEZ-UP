package com.ez.hana.admin.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.admin.service.AdBoardService;
import com.ez.hana.vo.BoardVO;

@RequestMapping("/admin/board")
@Controller
public class AdBoardController {

	@Autowired
	AdBoardService adBoardService;
	
	//전체글 조회
	@GetMapping("/list")
	public ModelAndView getBoardList() {
		ModelAndView mav = new ModelAndView("admin/board/boardList");
		List<BoardVO> list = adBoardService.getBoardList();
		mav.addObject("list", list);

		return mav;
	}

	//전체글 조회
	@GetMapping("/hidden")
	public ModelAndView getBoardHiddenList() {
		ModelAndView mav = new ModelAndView("admin/board/hidden");
		List<BoardVO> list = adBoardService.getBoardHiddenList();
		mav.addObject("hiddenlist", list);
		
		return mav;
	}
	
	
}
