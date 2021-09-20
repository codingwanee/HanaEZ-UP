package com.ez.hana.dao;

import java.util.List;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.ez.hana.vo.BoardVO;
import com.ez.hana.vo.CommentVO;

@Repository
public class BoardDAOImpl implements BoardDAO {

	@Autowired
	private SqlSessionTemplate sqlSession;
	
	// 목록조회
	@Override
	public List<BoardVO> selectAll() {
		List<BoardVO> list = sqlSession.selectList("boardMapper.selectAll");
		return list;
	}
	
	// 숨긴글 조회
	@Override
	public List<BoardVO> selectAllHidden() {
		List<BoardVO> list = sqlSession.selectList("boardMapper.selectAllHidden");
		return list;
	}

	// 상세조회
	@Override
	public BoardVO selectOne(int num) {
		BoardVO boardVO = sqlSession.selectOne("boardMapper.selectOne", num);
		return boardVO;
	}
	
	// 상세글 조회시 조회수 증가
	@Override
	public void updateViewCnt(int num) {
		sqlSession.update("boardMapper.updateViewCnt", num);
	}

	// 새글 등록
	@Override
	public void insertOne(BoardVO boardVO) {
		sqlSession.insert("boardMapper.insertOne", boardVO);
	}
	
	// 답글 등록
	@Override
	public void insertReply(BoardVO boardVO) {
		sqlSession.insert("boardMapper.insertReply", boardVO);		
	}

	// 글 수정
	@Override
	public void updateOne(BoardVO boardVO) {
		sqlSession.selectOne("boardMapper.updateOne", boardVO);
	}

	// 글 삭제
	@Override
	public void deleteOne(int num) {
		sqlSession.selectOne("boardMapper.deleteOne", num);
	}
	
	
	
	/////////////////////////// 댓글 ////////////////////////////////
	
	// 댓글 조회
	@Override
	public List<CommentVO> selectAllComments(int num) {
		List<CommentVO> commentList = sqlSession.selectList("boardMapper.selectAllComment", num);
		return commentList;
	}

	// 댓글 등록
	@Override
	public void insertComment(CommentVO commentVO) {
		sqlSession.insert("boardMapper.insertComment", commentVO);
	}
	
	// 댓글 등록 시 원글 댓글수 증가
	@Override
	public void updateCommentCnt(int num) {
		sqlSession.update("boardMapper.updateCmtCnt", num);
	}
	
	// 댓글 수정
	@Override
	public void updateComment(CommentVO commentVO) {
		sqlSession.update("boardMapper.updateComment", commentVO);
	}

	// 댓글 삭제
	@Override
	public void deleteComment(CommentVO commentVO) {
		sqlSession.delete("boardMapper.deleteComment", commentVO);		
	}
	



}
