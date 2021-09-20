package com.ez.hana.admin.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ez.hana.dao.BoardDAO;
import com.ez.hana.vo.BoardVO;

@Service
public class AdBoardServiceImpl implements AdBoardService {

	@Autowired
	BoardDAO boardDAO;
	
	// 전체글 조회
	@Override
	public List<BoardVO> getBoardList()  {
		List<BoardVO> list = boardDAO.selectAll();
		return list;
	}

	// 숨긴글 조회
	@Override
	public List<BoardVO> getBoardHiddenList()  {
		List<BoardVO> list = boardDAO.selectAllHidden();
		return list;
	}

}
