package com.ez.hana.home.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.ez.hana.home.service.BoardService;
import com.ez.hana.vo.BoardVO;
import com.ez.hana.vo.CommentVO;
import com.ez.hana.vo.MemberVO;

@RequestMapping("/board")
@Controller
public class BoardController {
	
	@Autowired
	private BoardService boardService;
	
	
	// 전체글 조회
	@RequestMapping
	public ModelAndView viewPostings() {	
		List<BoardVO> list = boardService.viewAllPostings();
		ModelAndView mav = new ModelAndView("home/board/board"); // viewName을 인자로 넘겼다
		mav.addObject("list", list); // 공유영역에 올리기		
		return mav;		
	}
	
	// 상세글 조회
	@GetMapping("/{num}")
	public ModelAndView viewPosting(@PathVariable("num") int num, HttpSession session) {
		ModelAndView mav = new ModelAndView("home/board/article");
		BoardVO boardVO = boardService.viewOnePosting(num);
		MemberVO loginVO = (MemberVO) session.getAttribute("loginVO");
		mav.addObject("boardVO", boardVO);
		mav.addObject("loginVO", loginVO);
		
		System.out.println("loginVO : " + loginVO.toString());
		
		return mav;
	}

	// 글쓰기 양식으로 이동
	@GetMapping("/write")
	public String writeForm() {
		return "home/board/write";
	}

	// 글쓰기
	@PostMapping("/write")
	public String doWrite(HttpServletRequest request, BoardVO boardVO) {
		HttpSession session = request.getSession();
		MemberVO loginVO = (MemberVO) session.getAttribute("loginVO");
		String writer = loginVO.getId();		
		boardVO.setWriter(writer);		
		boardService.registerNewPost(boardVO);	
		return "redirect:/board";
	}	
	
	// 답글쓰기
	@PostMapping("/reply")
	public String doReply(BoardVO boardVO) {
		boardService.doReply(boardVO);
		return "redirect:board/" + boardVO.getNum();
	}
	
	///////////////// 댓글 /////////////////////
	
	//댓글조회
	@ResponseBody
	@GetMapping("/comment/{num}")
	public List<CommentVO> getCommentList(@PathVariable("num") int num) {
		List<CommentVO> commentList = boardService.getCommentList(num);
		return commentList;
	}
	
	// 댓글쓰기
//	@PostMapping("/comment/{num}")
//	public void addComment(CommentVO commentVO, @PathVariable("num") int num) {
	@ResponseBody
	@PostMapping("/comment")
	public void addComment(CommentVO commentVO) {
		System.out.println(commentVO.toString());
		boardService.registerNewComment(commentVO);
	}
	

}
