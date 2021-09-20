package com.ez.hana.dao;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.ez.hana.vo.EmployeeVO;

@Repository
public class EmployeeDAOImpl implements EmployeeDAO {

	@Autowired
	SqlSessionTemplate sqlSession;
	
	/**
	 * 직원 로그인
	 */
	@Override
	public EmployeeVO login(EmployeeVO employeeVO) {
		return sqlSession.selectOne("employeeMapper.login", employeeVO);
	}
	
	
}
