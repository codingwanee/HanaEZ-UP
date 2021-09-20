package com.ez.hana.dao;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.ez.hana.vo.MemberVO;

@Repository
public class MemberDAOImpl implements MemberDAO {

	@Autowired
	private SqlSessionTemplate sqlSession;
	
	@Override
	public MemberVO login(MemberVO memberVO) {
		MemberVO loginVO = sqlSession.selectOne("memberMapper.login", memberVO);
		return loginVO;
	}
	
	@Override
	public void join(MemberVO memberVO) {
		sqlSession.insert("memberMapper.insertOne", memberVO);		
	}
	
	@Override
	public MemberVO selectOne(MemberVO loginVO) {
		MemberVO memberVO = sqlSession.selectOne("memberMapper.selectOne", loginVO);
		return memberVO;
	}
	
	@Override
	public MemberVO selectOneById(String id) {
		MemberVO memberVO = sqlSession.selectOne("memberMapper.selectOne", id);
		return memberVO;
	}
	
	// 인증상태 변경
	@Override
	public void updateCertStatus(MemberVO memberVO) {
		sqlSession.update("memberMapper.updateStatus", memberVO);
	}
}
