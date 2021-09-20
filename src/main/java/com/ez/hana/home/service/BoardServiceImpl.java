package com.ez.hana.home.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ez.hana.dao.BoardDAO;
import com.ez.hana.vo.BoardVO;
import com.ez.hana.vo.CommentVO;

@Service
public class BoardServiceImpl implements BoardService {

	@Autowired
	private BoardDAO boardDAO;


	// 전체 게시글 조회
	@Override
	public List<BoardVO> viewAllPostings() {
		List<BoardVO> list = boardDAO.selectAll();
		return list;
	}

	// 상세 게시글 조회
	@Override
	public BoardVO viewOnePosting(int num) {
		BoardVO boardVO = boardDAO.selectOne(num);
		boardDAO.updateViewCnt(num);
		return boardVO;
	}	
	
	// 새글 등록
	@Override
	public void registerNewPost(BoardVO boardVO) {
		boardDAO.insertOne(boardVO);		
	}

	// 글 수정
	@Override
	public void modifyArticle(BoardVO boardVO) {
		boardDAO.updateOne(boardVO);
	}	

	// 글 삭제
	@Override
	public void deleteArticle(int num) {
		boardDAO.deleteOne(num);		
	}
	
	// 답글 등록
	@Override
	public void doReply(BoardVO boardVO) {
		boardDAO.insertReply(boardVO);
	}
	
	
	//////////////////////// 댓글 //////////////////////////////////
	// 댓글 목록
	@Override
	public List<CommentVO> getCommentList(int num) {
		List<CommentVO> commentList = boardDAO.selectAllComments(num);
		return commentList;
	}
	
	// 댓글 등록
	@Override
	public void registerNewComment(CommentVO commentVO) {
		boardDAO.insertComment(commentVO);		
		boardDAO.updateCommentCnt(commentVO.getBoardNum());
	}
	
	// 댓글 수정
	@Override
	public void modifyComment(CommentVO commentVO) {
		boardDAO.updateComment(commentVO);
	}
	
	// 댓글 삭제
	@Override
	public void deleteComment(CommentVO commentVO) {
		boardDAO.deleteComment(commentVO);
	}
	


}
