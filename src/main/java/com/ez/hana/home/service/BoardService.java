package com.ez.hana.home.service;

import java.util.List;

import com.ez.hana.vo.BoardVO;
import com.ez.hana.vo.CommentVO;

public interface BoardService {
	
	/**
	 * 전체 게시글 조회
	 * @return list
	 */
	public List<BoardVO> viewAllPostings();

	/**
	 * 상세 게시글 조회
	 * @return boardVO
	 */
	public BoardVO viewOnePosting(int num);

	/**
	 * 새글등록
	 * @param boardVO
	 */
	public void registerNewPost(BoardVO boardVO);
	
	/**
	 * 게시글 수정
	 */
	public void modifyArticle(BoardVO boardVO);
	
	/**
	 * 게시글 삭제
	 */
	public void deleteArticle(int num);
	
	/**
	 * 답글등록
	 * @param boardVO
	 */
	public void doReply(BoardVO boardVO);
	
	
	/**
	 * 댓글목록 조회
	 */
	public List<CommentVO> getCommentList(int num);	

	/**
	 * 댓글등록
	 * @param commentVO
	 */
	public void registerNewComment(CommentVO commentVO);
	
	/**
	 * 댓글수정
	 */
	public void modifyComment(CommentVO commentVO);
	
	/**
	 * 댓글삭제
	 */
	public void deleteComment(CommentVO commentVO);


}
