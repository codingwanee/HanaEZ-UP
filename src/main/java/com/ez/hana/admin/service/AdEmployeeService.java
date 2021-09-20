package com.ez.hana.admin.service;

import com.ez.hana.vo.EmployeeVO;

public interface AdEmployeeService {

	/**
	 * 직원 로그인
	 */
	public EmployeeVO login(EmployeeVO empVO);

}
