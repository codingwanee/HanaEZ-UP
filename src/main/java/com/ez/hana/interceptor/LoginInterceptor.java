package com.ez.hana.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import com.ez.hana.vo.MemberVO;

public class LoginInterceptor extends HandlerInterceptorAdapter {

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {

		if (handler instanceof HandlerMethod) {
			HandlerMethod method = (HandlerMethod) handler;
		}

		// 로그인 여부 체크
		HttpSession session = request.getSession();
		MemberVO loginVO = (MemberVO) session.getAttribute("loginVO");

		// 로그인이 되어있지 않으면 글쓰기 기능으로 보내지 않음
		if (loginVO == null) {

			// 요청을 보낸 uri 가지고 오기
			String uri = request.getRequestURI();
			uri = uri.substring(request.getContextPath().length()+1);

			// uri 뒤에 날라오는 parameter도 가지고 오기 ( no=24 형태로 날라옴)
			String query = request.getQueryString();
			System.out.println("query : " + query);

			// 날라오는 parameter가 있을경우 uri 뒤에 query를 붙여줌
			if (query != null && query.length() != 0)
				uri = uri + "?" + query;

			session.setAttribute("dest", uri);

			response.sendRedirect(request.getContextPath() + "/login");
			return false;
		}

		return true;
	}

}
