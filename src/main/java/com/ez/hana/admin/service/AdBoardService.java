package com.ez.hana.admin.service;

import com.ez.hana.vo.BoardVO;

import java.util.List;

public interface AdBoardService {
	
	/**
	 * 전체 글 조회
	 * @return list 게시판 글 목록
	 */
	public List<BoardVO> getBoardList();

	/**
	 * 숨긴 글 조회
	 * @return list 게시판 글 목록
	 */
	public List<BoardVO> getBoardHiddenList();

}
