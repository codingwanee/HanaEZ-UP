package com.ez.hana.dao;

import java.util.List;

import com.ez.hana.vo.BoardVO;
import com.ez.hana.vo.CommentVO;

public interface BoardDAO {
	
	/**
	 * 게시판 목록 불러오기
	 */
	public List<BoardVO> selectAll();
	
	/**
	 * 숨긴글 조회
	 */
	public List<BoardVO> selectAllHidden();
	
	/**
	 * 상세글 조회
	 * @param postId 게시물번호
	 */
	public BoardVO selectOne(int postId);
	

	/**
	 * 상세글 조회시 조회수 증가
	 * @param num
	 */
	public void updateViewCnt(int num);
	
	/**
	 * 새글등록
	 */
	public void insertOne(BoardVO boardVO);
	
	/**
	 * 글 수정
	 * @param boardVO 게시물 객체
	 */
	public void updateOne(BoardVO boardVO);
	
	/**
	 * 글 삭제
	 * @param postId 게시물번호
	 */
	public void deleteOne(int postId);

	/**
	 * 답글 등록
	 * @param boardVO
	 */
	public void insertReply(BoardVO boardVO);
	
	
	
	
	/////////////////////////// 댓글 //////////////////////////////
	
	/**
	 * 댓글 조회
	 * return List<CommentVO>
	 */
	public List<CommentVO> selectAllComments(int num);
	
	/**
	 * 댓글등록
	 * @param commentVO 게시물 객체
	 */
	public void insertComment(CommentVO commentVO);
	
	/**
	 * 댓글 등록 시 원글에서 댓글수 증가
	 */
	public void updateCommentCnt(int num);
	
	/**
	 * 댓글수정
	 * @param commentVO
	 */
	public void updateComment(CommentVO commentVO);
	
	/**
	 * 댓글삭제
	 */
	public void deleteComment(CommentVO commentVO);


	



}
