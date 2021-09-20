package com.ez.hana.dao;

import com.ez.hana.vo.MemberVO;

public interface MemberDAO {
	
	/**
	 * 로그인
	 * @param memberVO 회원 객체
	 */
	public MemberVO login(MemberVO memberVO);
	
	
	/**
	 * 회원가입
	 * @param memberVO
	 */
	public void join(MemberVO memberVO);
	
	
	/**
	 * 회원 상세조회(마이페이지)
	 */
	public MemberVO selectOne(MemberVO loginVO);


	/**
	 * 아이디 중복조회
	 * @param id
	 * @return
	 */
	public MemberVO selectOneById(String id);

	/**
	 * 비대면 인증상태 승인으로 변경
	 * @param string
	 */
	public void updateCertStatus(MemberVO memberVO);

}
