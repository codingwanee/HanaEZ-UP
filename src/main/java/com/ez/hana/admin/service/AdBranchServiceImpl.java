package com.ez.hana.admin.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ez.hana.dao.BranchDAO;
import com.ez.hana.vo.BranchVO;

@Service
public class AdBranchServiceImpl implements AdBranchService {

	@Autowired
	BranchDAO branchDAO;
	
	@Override
	public List<BranchVO> showAllBranches() {
		List<BranchVO> branchList = branchDAO.selectAll();
		return branchList;
	}
	
	@Override
	public void registerBranch(BranchVO branchVO) {
		System.out.println("register service entered . . .");
		branchDAO.insert(branchVO);		
	}

	
}
