package com.ez.hana.home.service;

import com.ez.hana.vo.MemberVO;

public interface MemberService {

	/**
	 * 로그인
	 */
	public MemberVO login(MemberVO loginVO);
	
	/**
	 * 회원 상세조회(마이페이지)
	 */
	public MemberVO mypage(MemberVO loginVO);

	/**
	 * 아이디 중복체크
	 * @param id
	 * @return bool
	 */
	public Boolean checkIdDuplicated(String id);
	
}
