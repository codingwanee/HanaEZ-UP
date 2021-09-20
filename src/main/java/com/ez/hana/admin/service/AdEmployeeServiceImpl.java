package com.ez.hana.admin.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ez.hana.dao.EmployeeDAO;
import com.ez.hana.vo.EmployeeVO;

@Service
public class AdEmployeeServiceImpl implements AdEmployeeService {
	
	@Autowired
	EmployeeDAO employeeDAO;
	
	
	/**
	 * 직원 로그인
	 */
	@Override
	public EmployeeVO login(EmployeeVO empVO) {
		return employeeDAO.login(empVO);
	};

}
